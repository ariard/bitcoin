#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test carve-out and RBF interactions"""

from test_framework.key import (
        ECKey
)

from test_framework.messages import (
        CTransaction,
        CTxIn,
        CTxInWitness,
        CTxOut,
        COutPoint,
        sha256,
        COIN,
        tx_from_hex,
)

from test_framework.util import (
        assert_equal
)

from test_framework.script import (
        CScript,
        hash160,
        OP_IF,
        OP_HASH160,
        OP_EQUAL,
        OP_ELSE,
        OP_ENDIF,
        OP_CHECKSIG,
        OP_SWAP,
        OP_SIZE,
        OP_NOTIF,
        OP_DROP,
        OP_CHECKMULTISIG,
        OP_EQUALVERIFY,
        OP_0,
        OP_2,
        OP_TRUE,
        SegwitV0SignatureHash,
        SIGHASH_ALL,
        SIGHASH_SINGLE,
        SIGHASH_ANYONECANPAY,
)

from test_framework.test_framework import BitcoinTestFramework

from test_framework.wallet import MiniWallet

def get_funding_redeemscript(funder_pubkey, fundee_pubkey):
    return CScript([OP_2, funder_pubkey.get_bytes(), fundee_pubkey.get_bytes(), OP_2, OP_CHECKMULTISIG])

def generate_funding_chan(wallet, coin, funder_pubkey, fundee_pubkey):
    witness_script = get_funding_redeemscript(funder_pubkey, fundee_pubkey)
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    funding_tx = CTransaction()
    funding_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
    funding_tx.vout.append(CTxOut(int(49.99998 * COIN), script_pubkey))
    funding_tx.rehash()

    wallet.sign_tx(funding_tx)
    return funding_tx

def generate_commitment_tx(funding_txid, funding_vout, funder_seckey, fundee_seckey, input_amount, input_script):

    anchor_output_script = CScript([OP_TRUE])
    # Note: this can be updated to match BOLT3 standard
    anchor_output_scriptpubkey = CScript([OP_0, sha256(anchor_output_script)])

    commitment_fee = 250 * 10
    commitment_tx = CTransaction()

    commitment_tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", 0x0))
    commitment_tx.vout.append(CTxOut(int(input_amount / 2) - commitment_fee, anchor_output_scriptpubkey))
    commitment_tx.vout.append(CTxOut(int(input_amount / 2), anchor_output_scriptpubkey))

    sig_hash = SegwitV0SignatureHash(input_script, commitment_tx, 0, SIGHASH_ALL, int(input_amount))
    funder_sig = funder_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = fundee_seckey.sign_ecdsa(sig_hash) + b'\x01'

    commitment_tx.wit.vtxinwit.append(CTxInWitness())
    commitment_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', funder_sig, fundee_sig, input_script]
    commitment_tx.rehash()

    return commitment_tx

def generate_chain_junk_tx(parent_txid, parent_vout, input_amount, sat_per_vbyte, nSequence):

    junk_txn = []

    junk_output_script = CScript([OP_TRUE])
    junk_output_scriptpubkey = CScript([OP_0, sha256(junk_output_script)])

    # Overpaid a bit in fees.
    junk_tx_fee = 316 * sat_per_vbyte

    first_junk_tx = CTransaction()
    first_junk_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), parent_vout), b"", nSequence))
    first_junk_tx.vout.append(CTxOut(int(input_amount - junk_tx_fee), junk_output_scriptpubkey))

    first_junk_tx.wit.vtxinwit.append(CTxInWitness())
    first_junk_tx.wit.vtxinwit[0].scriptWitness.stack = [junk_output_script]

    first_junk_tx.wit.vtxinwit.append(CTxInWitness())
    first_junk_tx.wit.vtxinwit[1].scriptWitness.stack = [junk_output_script]

    first_junk_tx.rehash()
    parent_txid = first_junk_tx.hash
    next_input_amount = input_amount - junk_tx_fee

    junk_txn.append(first_junk_tx)

    # Note: bumping this variable to 24 should get a "too-long-mempool-chain" error.
    # Default unconfirmed ancestor: 25
    for i in range(0, 23):

        junk_tx = CTransaction()
        junk_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 0), b"", nSequence))
        junk_tx.vout.append(CTxOut(int(next_input_amount - junk_tx_fee), junk_output_scriptpubkey))

        junk_tx.wit.vtxinwit.append(CTxInWitness())
        junk_tx.wit.vtxinwit[0].scriptWitness.stack = [junk_output_script]

        junk_tx.rehash()

        junk_txn.append(junk_tx)

        parent_txid = junk_tx.hash
        next_input_amount = next_input_amount - junk_tx_fee

    return junk_txn

def generate_replacement_tx(commitment_txid, commitment_vout, input_amount, sat_per_vbyte, nsequence):

    replacement_tx_fee = 200 * sat_per_vbyte

    anyone_can_spend_output_script = CScript([OP_TRUE])
    anyone_can_spend_scriptpubkey = CScript([OP_0, sha256(anyone_can_spend_output_script)])

    replacement_tx = CTransaction()
    replacement_tx.vin.append(CTxIn(COutPoint(int(commitment_txid, 16), commitment_vout), b"", nsequence))
    replacement_tx.vout.append(CTxOut(int(input_amount - replacement_tx_fee), anyone_can_spend_scriptpubkey))

    replacement_tx.wit.vtxinwit.append(CTxInWitness())
    replacement_tx.wit.vtxinwit[0].scriptWitness.stack = [anyone_can_spend_output_script]

    return replacement_tx

class MempoolLongChainTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2

    def test_carveout_rbf(self):
        alice = self.nodes[0]
        alice_seckey = ECKey()
        alice_seckey.generate(True)

        bob = self.nodes[1]
        bob_seckey = ECKey()
        bob_seckey.generate(True)

        self.generate(alice, 501)

        self.sync_all()

        self.connect_nodes(0, 1)

        coin_1 = self.wallet.get_utxo()

        wallet = self.wallet

        # Generate funding transaction opening channel between Alice and Bob.
        ab_funding_tx = generate_funding_chan(wallet, coin_1, alice_seckey.get_pubkey(), bob_seckey.get_pubkey())

        # Propagate and confirm funding transaction.
        ab_funding_txid = alice.sendrawtransaction(hexstring=ab_funding_tx.serialize().hex(), maxfeerate=0)

        self.sync_all()

        assert ab_funding_txid in alice.getrawmempool()
        assert ab_funding_txid in bob.getrawmempool()

        # We mine one block the Alice - Bob channel is opened.
        self.generate(alice, 1)
        assert_equal(len(alice.getrawmempool()), 0)
        assert_equal(len(bob.getrawmempool()), 0)

        coin = self.wallet.get_utxo()

        # Generate commitment transaction with 2 anchor output
        funding_redeemscript = get_funding_redeemscript(alice_seckey.get_pubkey(), bob_seckey.get_pubkey())
        input_amount = 49.99998 * COIN
        ab_commitment_tx = generate_commitment_tx(ab_funding_txid, 0, alice_seckey, bob_seckey, input_amount, funding_redeemscript)

        ab_commitment_txid = alice.sendrawtransaction(hexstring=ab_commitment_tx.serialize().hex(), maxfeerate=0)

        self.sync_all()

        assert ab_commitment_txid in alice.getrawmempool()
        assert ab_commitment_txid in bob.getrawmempool()

        junk_txn = generate_chain_junk_tx(ab_commitment_txid, 0, (input_amount / 2) - (250 * 10), 2, 0)

        ret_txid = []

        for tx in junk_txn:
            txid = alice.sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0)
            ret_txid.append(txid)

        self.sync_all()

        for txid in ret_txid:
            assert txid in alice.getrawmempool()
            assert txid in bob.getrawmempool()

        replacement_tx = generate_replacement_tx(ab_commitment_txid, 0, (input_amount / 2) - (250 * 10), 100, 0)

        replacement_txid = alice.sendrawtransaction(hexstring=replacement_tx.serialize().hex(), maxfeerate=0)

        self.sync_all()

        assert replacement_txid in alice.getrawmempool()
        assert replacement_txid in bob.getrawmempool()

        for txid in ret_txid:
            assert not txid in alice.getrawmempool()
            assert not txid in bob.getrawmempool()

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_carveout_rbf()

if __name__ == '__main__':
    MempoolLongChainTest().main()
