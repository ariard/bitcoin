#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test network topology aware pinning"""

import time

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
        assert_equal,
        assert_raises_rpc_error
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

def generate_asymmetric_commitment_tx(funding_txid, funding_vout, alice_seckey, bob_seckey, input_amount, input_script):

    alice_pubkey = alice_seckey.get_pubkey()
    alice_anchor_output_script = CScript([alice_pubkey.get_bytes(), OP_CHECKSIG])
    alice_anchor_output_scriptpubkey = CScript([OP_0, sha256(alice_anchor_output_script)])

    bob_pubkey = bob_seckey.get_pubkey()
    bob_anchor_output_script = CScript([bob_pubkey.get_bytes(), OP_CHECKSIG])
    bob_anchor_output_scriptpubkey = CScript([OP_0, sha256(bob_anchor_output_script)])

    alice_commitment_fee = 250 * 10
    alice_commitment_tx = CTransaction()

    alice_commitment_tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", 0x0))
    alice_commitment_tx.vout.append(CTxOut(int(input_amount / 2) - alice_commitment_fee, alice_anchor_output_scriptpubkey))
    alice_commitment_tx.vout.append(CTxOut(int(input_amount / 2), bob_anchor_output_scriptpubkey))

    sig_hash = SegwitV0SignatureHash(input_script, alice_commitment_tx, 0, SIGHASH_ALL, int(input_amount))
    funder_sig = alice_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = bob_seckey.sign_ecdsa(sig_hash) + b'\x01'

    alice_commitment_tx.wit.vtxinwit.append(CTxInWitness())
    alice_commitment_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', funder_sig, fundee_sig, input_script]
    alice_commitment_tx.rehash()

    bob_commitment_fee = 250 * 10 - 1 #For the asymmetry
    bob_commitment_tx = CTransaction()

    bob_commitment_tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", 0x0))
    bob_commitment_tx.vout.append(CTxOut(int(input_amount / 2) - bob_commitment_fee, alice_anchor_output_scriptpubkey))
    bob_commitment_tx.vout.append(CTxOut(int(input_amount / 2), bob_anchor_output_scriptpubkey))

    sig_hash = SegwitV0SignatureHash(input_script, bob_commitment_tx, 0, SIGHASH_ALL, int(input_amount))
    funder_sig = alice_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = bob_seckey.sign_ecdsa(sig_hash) + b'\x01'

    bob_commitment_tx.wit.vtxinwit.append(CTxInWitness())
    bob_commitment_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', funder_sig, fundee_sig, input_script]
    bob_commitment_tx.rehash()

    return (alice_commitment_tx, bob_commitment_tx)

def generate_cpfp_txn(alice_commitment_txid, on_alice_anchor_vout, bob_commitment_txid, on_bob_anchor_vout, alice_seckey, bob_seckey, input_amount_one, input_amount_two):

    alice_pubkey = alice_seckey.get_pubkey()
    alice_anchor_output_script = CScript([alice_pubkey.get_bytes(), OP_CHECKSIG])

    alice_cpfp_on_alice_fee = 250 * 10
    alice_cpfp_on_alice_tx = CTransaction()

    alice_cpfp_on_alice_tx.vin.append(CTxIn(COutPoint(int(alice_commitment_txid, 16), on_alice_anchor_vout), b"", 0x0))
    alice_cpfp_on_alice_tx.vout.append(CTxOut(int(input_amount_one - alice_cpfp_on_alice_fee), alice_anchor_output_script))

    sig_hash = SegwitV0SignatureHash(alice_anchor_output_script, alice_cpfp_on_alice_tx, 0, SIGHASH_ALL, int(input_amount_one))
    anchor_sig = alice_seckey.sign_ecdsa(sig_hash) + b'\x01'

    alice_cpfp_on_alice_tx.wit.vtxinwit.append(CTxInWitness())
    alice_cpfp_on_alice_tx.wit.vtxinwit[0].scriptWitness.stack = [anchor_sig, alice_anchor_output_script]
    alice_cpfp_on_alice_tx.rehash()

    alice_cpfp_on_bob_fee = 250 * 10
    alice_cpfp_on_bob_tx = CTransaction()

    alice_cpfp_on_bob_tx.vin.append(CTxIn(COutPoint(int(bob_commitment_txid, 16), on_bob_anchor_vout), b"", 0x0))
    alice_cpfp_on_bob_tx.vout.append(CTxOut(int(input_amount_two - alice_cpfp_on_bob_fee), alice_anchor_output_script))

    sig_hash = SegwitV0SignatureHash(alice_anchor_output_script, alice_cpfp_on_bob_tx, 0, SIGHASH_ALL, int(input_amount_two))
    anchor_sig = alice_seckey.sign_ecdsa(sig_hash) + b'\x01'

    alice_cpfp_on_bob_tx.wit.vtxinwit.append(CTxInWitness())
    alice_cpfp_on_bob_tx.wit.vtxinwit[0].scriptWitness.stack = [anchor_sig, alice_anchor_output_script]
    alice_cpfp_on_bob_tx.rehash()

    return (alice_cpfp_on_alice_tx, alice_cpfp_on_bob_tx)

class NetworkTopologyAwarePinning(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2

    def test_network_topology_aware_pinning(self):
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


        # Generate commitment transaction with 2 anchor output
        funding_redeemscript = get_funding_redeemscript(alice_seckey.get_pubkey(), bob_seckey.get_pubkey())
        input_amount = 49.99998 * COIN
        (alice_commitment_tx, bob_commitment_tx) = generate_asymmetric_commitment_tx(ab_funding_txid, 0, alice_seckey, bob_seckey, input_amount, funding_redeemscript)

        self.disconnect_nodes(0, 1)

        alice_commitment_txid = alice.sendrawtransaction(hexstring=alice_commitment_tx.serialize().hex(), maxfeerate=0)

        assert alice_commitment_txid in alice.getrawmempool()
        assert not alice_commitment_txid in bob.getrawmempool()
 
        input_amount_two = bob_commitment_tx.vout[0].nValue

        bob_commitment_txid = bob.sendrawtransaction(hexstring=bob_commitment_tx.serialize().hex(), maxfeerate=0)
        assert bob_commitment_txid in bob.getrawmempool()
        assert not bob_commitment_txid in alice.getrawmempool()

        self.connect_nodes(0, 1)

        assert alice_commitment_txid in alice.getrawmempool()
        assert bob_commitment_txid in bob.getrawmempool()

        input_amount_one = (input_amount / 2) - (250 * 10)
        (alice_cpfp_on_alice, alice_cpfp_on_bob) = generate_cpfp_txn(alice_commitment_txid, 0, bob_commitment_txid, 0, alice_seckey, bob_seckey, input_amount_one, input_amount_two)

        alice_cpfp_on_alice_txid = alice.sendrawtransaction(hexstring=alice_cpfp_on_alice.serialize().hex(), maxfeerate=0)

        assert alice_cpfp_on_alice_txid in alice.getrawmempool()
        assert not alice_cpfp_on_alice_txid in bob.getrawmempool()

        self.log.info("Alice CFPP {} on Alice commitment tx {} propagates inside Alice mempool".format(alice_cpfp_on_alice_txid, alice_commitment_txid))
        self.log.info("Alice CFPP {} on Alice commitment tx {} does not propagate inside Bob mempool".format(alice_cpfp_on_alice_txid, alice_commitment_txid))

        assert bob.testmempoolaccept([alice_cpfp_on_bob.serialize().hex()])[0]["allowed"]

        self.log.info("Alice CFPP {} on Bob commitment tx {} does propagate on top of Bob commitment tx".format(alice_cpfp_on_bob.hash, bob_commitment_txid))

        assert_raises_rpc_error(-25, "bad-txns-inputs-missingorspent", alice.sendrawtransaction, alice_cpfp_on_bob.serialize().hex(), 0)

        self.log.info("Alice CPFP {} on Bob commitment tx {} does not propagate from Alice mempool".format(alice_cpfp_on_bob.hash, bob_commitment_txid))

        coin_2 = self.wallet.get_utxo()
 
        random_tx = generate_funding_chan(wallet, coin_2, alice_seckey.get_pubkey(), bob_seckey.get_pubkey())

        random_txid = alice.sendrawtransaction(hexstring=random_tx.serialize().hex(), maxfeerate=0)
        bob.sendrawtransaction(hexstring=random_tx.serialize().hex(), maxfeerate=0)

        assert random_txid in alice.getrawmempool()
        assert random_txid in bob.getrawmempool()

        assert_equal(len(alice.getrawmempool()), 3) # alice_commitment_tx + alice_cpfp_on_alice_tx + random_txid
        assert_equal(len(bob.getrawmempool()), 2) # bob_commitment_tx + random_txid

        self.log.info("By partitioning network mempools with asymmetric valid commitment transactions, high-CPFP can be jammed")

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_network_topology_aware_pinning()

if __name__ == '__main__':
    NetworkTopologyAwarePinning().main()
