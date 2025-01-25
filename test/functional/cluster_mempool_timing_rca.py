#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test replacement cyling attacks - Timing Variant - Cluster Mempool"""

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
        assert_greater_than,
        gen_return_txouts,
        create_lots_of_big_transactions,
        assert_raises_rpc_error
)

from test_framework.wallet_util import generate_keypair

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
        OP_RETURN,
        OP_TRUE,
        SegwitV0SignatureHash,
        SIGHASH_ALL,
        SIGHASH_SINGLE,
        SIGHASH_ANYONECANPAY,
)

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework

from test_framework.wallet import MiniWallet

CUSTOM_MEMPOOL_EXPIRY = 1 #hours

#def generate_batch_transaction(wallet, coin, input_amount, sat_per_vbyte, nSequence, mallet_pubkey_one, mallet_pubkey_two, alice_cpfp_pubkey):
#
#    payout_output_script = CScript([OP_TRUE])
#    payout_output_scriptpubkey = CScript([OP_0, sha256(payout_output_script)])
#
#    mallet_output_script_one = CScript([mallet_pubkey_one, OP_CHECKSIG])
#    mallet_output_scriptpubkey_one = CScript([OP_0, sha256(mallet_output_script_one)])
#    mallet_output_script_two = CScript([mallet_pubkey_two, OP_CHECKSIG])
#    mallet_output_scriptpubkey_two = CScript([OP_0, sha256(mallet_output_script_two)])
#
#    alice_cpfp_output_script = CScript([alice_cpfp_pubkey, OP_CHECKSIG])
#    alice_cpfp_output_scriptpubkey = CScript([OP_0, sha256(alice_cpfp_output_script)])
#
#    payout_amount = 10000000
#
#    payout_tx_fee = 534 * sat_per_vbyte
#    payout_tx = CTransaction()
#    payout_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))
#
#    payout_tx.vout.append(CTxOut(int(input_amount - payout_tx_fee - 10 * payout_amount), payout_output_scriptpubkey))
#    # TODO: we use OP_TRUE style of spending for now.
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout Mallet One
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout Mallet Two
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout Alice CPFP
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 4
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 5
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 6
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 7
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 8
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 9
#    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 10
#    payout_tx.rehash()
#
#    wallet.sign_tx(payout_tx)
#
#    return payout_tx

#def generate_single_tx(wallet, coin, input_amount, sat_per_vbyte, nSequence):
#
#    single_tx_output_script = CScript([OP_TRUE])
#    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])
#
#    single_tx_output_amount = 100000
#
#    single_tx_fee = 190 * sat_per_vbyte
#    single_tx = CTransaction()
#    single_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))
#
#    single_tx.vout.append(CTxOut(int(single_tx_output_amount), single_tx_output_scriptpubkey))
#    single_tx.rehash()
#
#    wallet.sign_tx(single_tx)
#
#    return single_tx

#def generate_single_tx_no_wallet(parent_txid, vout, input_amount, sat_per_vbyte, nSequence):
#
#    single_tx_output_script = CScript([OP_TRUE])
#    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])
#
#    single_tx_fee = 190 * sat_per_vbyte
#    single_tx_output_amount = input_amount - single_tx_fee
#
#    single_tx = CTransaction()
#    single_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), vout), b"", nSequence))
#    single_tx.vout.append(CTxOut(int(single_tx_output_amount), single_tx_output_scriptpubkey))
#
#    single_tx.wit.vtxinwit.append(CTxInWitness())
#    single_tx.wit.vtxinwit[0].scriptWitness.stack = [single_tx_output_script]
#
#    single_tx.rehash()
#
#    return single_tx

#def generate_big_single_tx(txid, vout, input_amount, sat_per_vbyte, nSequence):
#
#    single_tx_output_script = CScript([OP_TRUE])
#    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])
#
#    opreturn_scriptpubkey = CScript([OP_RETURN, b'\x01'*67437])
#
#    single_tx_fee = 67437 * sat_per_vbyte
#    single_tx = CTransaction()
#    single_tx.vin.append(CTxIn(COutPoint(int(txid, 16), vout), b"", nSequence))
#
#    single_tx.vout.append(CTxOut(int(input_amount - single_tx_fee), single_tx_output_scriptpubkey))
#    single_tx.vout.append(CTxOut(int(0), opreturn_scriptpubkey))
#
#    single_tx.wit.vtxinwit.append(CTxInWitness())
#    single_tx.wit.vtxinwit[0].scriptWitness.stack = [single_tx_output_script]
#
#    single_tx.rehash()
#
#    return single_tx

#def generate_fanout_tx(wallet, coin, input_amount, sat_per_vbyte, nSequence):
#
#    single_tx_output_script = CScript([OP_TRUE])
#    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])
#
#    amount = 10000000
#    single_tx_fee = 2000 * sat_per_vbyte
#    single_tx = CTransaction()
#    single_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))
#
#    for i in range(0, 50):
#        single_tx.vout.append(CTxOut(amount, single_tx_output_scriptpubkey))
#    single_tx.rehash()
#
#    wallet.sign_tx(single_tx)
#    return single_tx

#def generate_chain_junk_tx(number_of_junk, parent_txid, parent_vout, input_amount, second_parent_txid, second_parent_vout, second_input_amount, sat_per_vbyte, nSequence):
#
#    junk_txn = []
#
#    junk_output_script = CScript([OP_TRUE])
#    junk_output_scriptpubkey = CScript([OP_0, sha256(junk_output_script)])
#
#    # Overpaid a bit in fees.
#    junk_tx_fee = 316 * sat_per_vbyte
#
#    first_junk_tx = CTransaction()
#    first_junk_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), parent_vout), b"", nSequence))
#    first_junk_tx.vin.append(CTxIn(COutPoint(int(second_parent_txid, 16), second_parent_vout), b"", nSequence))
#    first_junk_tx.vout.append(CTxOut(int(input_amount + second_input_amount - junk_tx_fee), junk_output_scriptpubkey))
#
#    first_junk_tx.wit.vtxinwit.append(CTxInWitness())
#    first_junk_tx.wit.vtxinwit[0].scriptWitness.stack = [junk_output_script]
#
#    first_junk_tx.wit.vtxinwit.append(CTxInWitness())
#    first_junk_tx.wit.vtxinwit[1].scriptWitness.stack = [junk_output_script]
#
#    first_junk_tx.rehash()
#    parent_txid = first_junk_tx.hash
#    next_input_amount = input_amount + second_input_amount - junk_tx_fee
#
#    junk_txn.append(first_junk_tx)
#
#    for i in range(0, number_of_junk - 1):
#
#        junk_tx = CTransaction()
#        junk_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 0), b"", nSequence))
#        junk_tx.vout.append(CTxOut(int(next_input_amount - junk_tx_fee), junk_output_scriptpubkey))
#
#        junk_tx.wit.vtxinwit.append(CTxInWitness())
#        junk_tx.wit.vtxinwit[0].scriptWitness.stack = [junk_output_script]
#
#        junk_tx.rehash()
#
#        junk_txn.append(junk_tx)
#
#        parent_txid = junk_tx.hash
#        next_input_amount = next_input_amount - junk_tx_fee
#
#    return junk_txn


def generate_single_tx(wallet, coin, input_amount, sat_per_vbyte, nSequence):

    single_tx_output_script = CScript([OP_TRUE])
    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])

    single_tx_fee = 190 * sat_per_vbyte
    single_tx = CTransaction()
    single_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))

    single_tx.vout.append(CTxOut(int(input_amount - single_tx_fee), single_tx_output_scriptpubkey))
    single_tx.rehash()

    wallet.sign_tx(single_tx)

    return single_tx

def generate_v3_single_tx_no_wallet(parent_txid, vout, input_amount, sat_per_vbyte, nSequence):

    single_tx_output_script = CScript([OP_TRUE])
    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])

    single_tx_fee = 200 * sat_per_vbyte
    single_tx_output_amount = input_amount - single_tx_fee

    single_tx = CTransaction()
    single_tx.version = 3
    single_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), vout), b"", nSequence))
    single_tx.vout.append(CTxOut(int(single_tx_output_amount), single_tx_output_scriptpubkey))

    single_tx.wit.vtxinwit.append(CTxInWitness())
    single_tx.wit.vtxinwit[0].scriptWitness.stack = [single_tx_output_script]

    single_tx.rehash()

    return single_tx

def generate_v3_package(wallet, coin, input_amount, sat_per_vbyte, nSequence):

    output_script = CScript([OP_TRUE])
    output_scriptpubkey = CScript([OP_0, sha256(output_script)])

    parent_tx_fee = 200 * sat_per_vbyte
    parent_tx = CTransaction()
    parent_tx.version = 3
    parent_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))

    parent_tx.vout.append(CTxOut(int(input_amount - parent_tx_fee), output_scriptpubkey))

    txid = parent_tx.rehash()

    wallet.sign_tx(parent_tx)

    child_tx_fee = 200 * sat_per_vbyte
    child_tx = CTransaction()
    child_tx.version = 3
    child_tx.vin.append(CTxIn(COutPoint(int(txid, 16), 0), b"", nSequence))

    child_tx.vout.append(CTxOut(int(input_amount - parent_tx_fee - child_tx_fee), output_scriptpubkey))

    child_tx.wit.vtxinwit.append(CTxInWitness())
    child_tx.wit.vtxinwit[0].scriptWitness.stack = [output_script]

    return (parent_tx, child_tx)

def generate_v3_rbf_multiple_parents(first_parent_txid, first_parent_vout, input_amount, second_parent_txid, second_parent_vout, second_input_amount, sat_per_vbyte, nSequence):

    output_script = CScript([OP_TRUE])
    output_scriptpubkey = CScript([OP_0, sha256(output_script)])

    rbf_tx_fee = 242 * sat_per_vbyte
    rbf_tx = CTransaction()
    rbf_tx.version = 3
    rbf_tx.vin.append(CTxIn(COutPoint(int(first_parent_txid, 16), first_parent_vout), b"", nSequence))
    rbf_tx.vin.append(CTxIn(COutPoint(int(second_parent_txid, 16), second_parent_vout), b"", nSequence))

    rbf_tx.vout.append(CTxOut(int(input_amount + second_input_amount - rbf_tx_fee), output_scriptpubkey))

    rbf_tx.wit.vtxinwit.append(CTxInWitness())
    rbf_tx.wit.vtxinwit[0].scriptWitness.stack = [output_script]

    rbf_tx.wit.vtxinwit.append(CTxInWitness())
    rbf_tx.wit.vtxinwit[1].scriptWitness.stack = [output_script]

    rbf_tx.rehash()

    return rbf_tx

class ReplacementCyclingTimingClusterTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 3

        self.extra_args = [["-datacarriersize=100000", "-maxmempool=5", "-mempoolexpiry=%d" % CUSTOM_MEMPOOL_EXPIRY],
            ["-datacarriersize=100000", "-maxmempool=5", "-mempoolexpiry=%d" % CUSTOM_MEMPOOL_EXPIRY],
            ["-datacarriersize=100000", "-maxmempool=5", "-mempoolexpiry=%d" % CUSTOM_MEMPOOL_EXPIRY]]

    #def fill_mempool(self, node, first_fanout_txid, second_fanout_txid):
    #    #self.log.info("Fill the mempool until eviction is triggered and the mempoolminfee rises")

    #    #self.log.info("Fill up the mempool with big txs with high sat per vbyte")
    #    counter = 0

    #    for i in range(0, 50):
    #        #self.log.info("Broadcasting Tx {}".format(counter))
 
    #        big_tx = generate_big_single_tx(first_fanout_txid, i, 10000000, 3, 0)

    #        big_txid = node.sendrawtransaction(big_tx.serialize().hex())

    #        counter += 1

    #    for i in range(0, 22):
    #        #self.log.info("Broadcasting Tx {}".format(counter))
 
    #        big_tx = generate_big_single_tx(second_fanout_txid, i, 10000000, 3, 0)

    #        big_txid = node.sendrawtransaction(big_tx.serialize().hex())

    #        counter += 1

    #    big_tx = generate_big_single_tx(second_fanout_txid, 23, 10000000, 3, 0)
    #    assert_raises_rpc_error(-26, "mempool full", node.sendrawtransaction, big_tx.serialize().hex(), 0)

    #    #self.log.info("Filling up the mempool done")

    #    mempool_gap = node.getmempoolinfo()["maxmempool"] - node.getmempoolinfo()["bytes"]

    #    #self.log.info("Mempool gap {}".format(mempool_gap))

    #    #self.log.info("Check that mempoolminfee is larger than minrelaytxfee")
    #    assert_equal(node.getmempoolinfo()['minrelaytxfee'], Decimal('0.00001000'))
    #    assert_greater_than(node.getmempoolinfo()['mempoolminfee'], Decimal('0.00001000'))

    #    mempoolminfee = node.getmempoolinfo()['mempoolminfee']
    #    #self.log.info("Mempoolminfee is {}".format(mempoolminfee))

    def test_replacement_cycling_timing_cluster(self):
        # Mary and Mallet are 2 Miners node
        # Mary and Mallet have equal odds to mine a block
        mary = self.nodes[0]
        mallet = self.nodes[1]

        # Alice is an Exchange node, i.e a Transaction Issuer.
        # Mallet is owning 2 balances at the exchange.
        alice = self.nodes[2]

        alice_wallet = self.wallet

        self.generate(mary, 501)

        self.sync_all()

        coin_carpet = self.wallet.get_utxo()
        coin_carpet_second = self.wallet.get_utxo()
        coin_carpet_third = self.wallet.get_utxo()

        single_tx = generate_single_tx(alice_wallet, coin_carpet, 50 * COIN, 1, 0)

        single_tx_txid = mary.sendrawtransaction(single_tx.serialize().hex())

        another_single_tx = generate_single_tx(alice_wallet, coin_carpet_second, 50 * COIN, 1, 0)

        another_single_tx_txid = mary.sendrawtransaction(another_single_tx.serialize().hex())

        another_another_single_tx = generate_single_tx(alice_wallet, coin_carpet_third, 50 * COIN, 1, 0)

        another_another_single_tx_txid = mary.sendrawtransaction(another_another_single_tx.serialize().hex())

        self.generate(mary, 1)

        assert_equal(0, len(mary.getrawmempool()))

        self.log.info("Starting Replacement Cycling Attack - Timing Cluster")

        mallet_epsilon_tx = generate_v3_single_tx_no_wallet(another_single_tx_txid, 0, another_single_tx.vout[0].nValue, 1, 0)

        mallet_epsilon_txid = mary.sendrawtransaction(hexstring=mallet_epsilon_tx.serialize().hex(), maxfeerate=0)

        mallet_child_epsilon_tx = generate_v3_single_tx_no_wallet(mallet_epsilon_txid, 0, mallet_epsilon_tx.vout[0].nValue, 1, 0)

        mallet_child_epsilon_txid = mary.sendrawtransaction(hexstring=mallet_child_epsilon_tx.serialize().hex(), maxfeerate=0)

        assert mallet_epsilon_txid in mary.getrawmempool()
        assert mallet_child_epsilon_txid in mary.getrawmempool()

        self.log.info("Epsilon Tx + Child Broadcast")

        assert_equal(2, len(mary.getrawmempool()))

        epsilon_entry_time = mary.getmempoolentry(mallet_epsilon_txid)['time']
        mary.setmocktime(epsilon_entry_time + 60 * 30)

        self.log.info("Time mocked for Mary")

        # Package: parent + single child at 1 virtual byte / satoshi
        self.log.info("Alice broadcasts a v3 package")

        coin_0 = self.wallet.get_utxo()

        alice_parent, alice_first_child = generate_v3_package(alice_wallet, coin_0, 50 * COIN, 5, 0)

        alice_parent_txid = alice_parent.rehash()
        alice_first_child_txid = alice_first_child.rehash()

        mary.submitpackage([alice_parent.serialize().hex(), alice_first_child.serialize().hex()])

        # bip 331 - SENDPACKAGES is not implemented yet.

        assert alice_parent_txid in mary.getrawmempool()
        assert alice_first_child_txid in mary.getrawmempool()

        assert_equal(4, len(mary.getrawmempool()))

        #self.log.info("BROADCAST #1 Alice mempool {}".format(alice.getrawmempool()))

        alice_parent_entry = mary.getmempoolentry(alice_parent_txid)

        # v3 rbf at 7 virtual byte / satoshi
        self.log.info("Mallet broadcasts a v3 rbf for Alice's rbf transaction")

        coin_1 = self.wallet.get_utxo()

        mallet_first_rbf = generate_v3_rbf_multiple_parents(alice_parent_txid, 0, alice_parent.vout[0].nValue, single_tx_txid, 0, single_tx.vout[0].nValue, 7, 0)

        mallet_first_rbf_txid = mallet_first_rbf.rehash()
        
        submitpackage_ret = mary.submitpackage([mallet_first_rbf.serialize().hex()])

        #self.log.info("Mallet Submitpackage Ret {}".format(submitpackage_ret))


        assert mallet_first_rbf_txid in mary.getrawmempool()
        assert alice_first_child_txid not in mary.getrawmempool()

        assert_equal(4, len(mary.getrawmempool()))

        #self.log.info("BROADCAST #2 Alice mempool {}".format(alice.getrawmempool()))

        # v3 rbf at 8 virtual byte / satoshi
        self.log.info("Mallet replaces its own v3 rbf")

        mallet_second_rbf = generate_v3_single_tx_no_wallet(single_tx_txid, 0, single_tx.vout[0].nValue, 9, 0)
        mallet_second_rbf_txid = mallet_second_rbf.rehash()

        submitpackage_ret = mary.submitpackage([mallet_second_rbf.serialize().hex()])

        #self.log.info("Mallet Submitpackage Second RBF Ret {}".format(submitpackage_ret))
        assert_equal(submitpackage_ret['package_msg'], 'success')

        assert_equal(4, len(mary.getrawmempool()))

        assert mallet_first_rbf_txid not in mary.getrawmempool()
        assert mallet_second_rbf_txid in mary.getrawmempool()

        #self.log.info("BROADCAST #3 Alice mempool {}".format(alice.getrawmempool()))

        # v3 rbf at 15 virtual byte / satoshi
        self.log.info("Alice broadcasts a bumped feerate child transaction on top of initial transaction")

        alice_first_rbf = generate_v3_single_tx_no_wallet(alice_parent_txid, 0, alice_parent.vout[0].nValue, 15, 0)
        alice_first_rbf_txid = alice_first_rbf.rehash()

        submitpackage_ret = mary.submitpackage([alice_first_rbf.serialize().hex()])
        assert_equal(submitpackage_ret['package_msg'], 'success')

        assert_equal(5, len(mary.getrawmempool()))

        assert mallet_first_rbf_txid not in mary.getrawmempool()
        assert mallet_second_rbf_txid in mary.getrawmempool()
        assert alice_first_rbf_txid in mary.getrawmempool()

        #self.log.info("BROADCAST #4 Alice mempool {}".format(alice.getrawmempool()))

        alice_first_rbf_entry = mary.getmempoolentry(alice_first_rbf_txid)

        # v3 rbf at 21 virtual byte / satoshi
        self.log.info("Mallet broadcasts a v3 rbf for Alice's bumped feerate transaction")

        mallet_third_rbf = generate_v3_rbf_multiple_parents(alice_parent_txid, 0, alice_parent.vout[0].nValue, single_tx_txid, 0, single_tx.vout[0].nValue, 21, 0)

        mallet_third_rbf_txid = mallet_third_rbf.rehash()

        submitpackage_ret = mary.submitpackage([mallet_third_rbf.serialize().hex()])
        assert_equal(submitpackage_ret['package_msg'], 'success')

        assert_equal(4, len(mary.getrawmempool()))

        assert mallet_third_rbf_txid in mary.getrawmempool()

        #self.log.info("BROADCAST #6 Alice mempool {}".format(alice.getrawmempool()))

        #self.log.info("Mallet Submitpackage Third RBF Ret {}".format(submitpackage_ret))

        # v3 rbf at 26 virtual byte / satoshi
        self.log.info("Mallet replaces his own v3 rbf")

        # We artificially broadcast a package to trigger package RBF
        mallet_package_parent_rbf = generate_v3_single_tx_no_wallet(single_tx_txid, 0, single_tx.vout[0].nValue, 1, 0)
        mallet_package_parent_rbf_txid = mallet_package_parent_rbf.rehash()

        mallet_package_child_rbf = generate_v3_rbf_multiple_parents(mallet_package_parent_rbf_txid, 0, mallet_package_parent_rbf.vout[0].nValue, another_another_single_tx_txid, 0, another_another_single_tx.vout[0].nValue, 28, 0)

        mallet_package_child_rbf_txid = mallet_package_child_rbf.rehash()

        # No package relay yet.
        mary_submitpackage_ret = mary.submitpackage([mallet_package_parent_rbf.serialize().hex(), mallet_package_child_rbf.serialize().hex()])
        assert_equal(mary_submitpackage_ret['package_msg'], 'success')

        #self.log.info("Mallet Submitpackage Package RBF Ret {}".format(mary_submitpackage_ret))

        # SHOULD HIT : "package RBF checks passed" in the logs
        #assert_equal(True, False)

        assert_equal(5, len(mary.getrawmempool()))

        assert alice_parent_txid in mary.getrawmempool()
        assert mallet_package_parent_rbf_txid in mary.getrawmempool()
        assert mallet_package_child_rbf_txid in mary.getrawmempool()

        mallet_package_parent_rbf_entry = mary.getmempoolentry(mallet_package_parent_rbf_txid)

        mallet_package_child_second_rbf = generate_v3_rbf_multiple_parents(mallet_epsilon_txid, 0, mallet_epsilon_tx.vout[0].nValue, another_another_single_tx_txid, 0, another_another_single_tx.vout[0].nValue, 38, 0)

        mallet_package_child_second_rbf_txid = mallet_package_child_second_rbf.rehash()

        mary_submitpackage_ret = mary.submitpackage([mallet_package_child_second_rbf.serialize().hex()])

        #self.log.info("Mallet Submitpackage Package RBF Ret {}".format(mary_submitpackage_ret))

        assert_equal(mary_submitpackage_ret['package_msg'], 'success')

        mallet_package_parent_rbf_entry = mary.getmempoolentry(mallet_package_parent_rbf_txid)

        mary.setmocktime(epsilon_entry_time + (60 * 30) * 3)

        assert_equal(4, len(mary.getrawmempool()))

        coin_sweep = self.wallet.get_utxo()

        sweep_tx = generate_single_tx(self.wallet, coin_sweep, 50.* COIN, 1, 0)

        sweep_txid = mary.sendrawtransaction(hexstring=sweep_tx.serialize().hex(), maxfeerate=0)

        assert_equal(3, len(mary.getrawmempool()))

        assert mallet_epsilon_txid not in mary.getrawmempool()
        assert mallet_package_child_second_rbf_txid not in mary.getrawmempool()

        sweep_entry = mary.getmempoolentry(sweep_txid)
 
        self.log.info("Mallet Transactions Expired")

        mary_block_template_vsize = alice_parent_entry['vsize'] + mallet_package_parent_rbf_entry['vsize'] + sweep_entry['vsize']
        mallet_block_template_vsize = alice_parent_entry['vsize'] + alice_first_rbf_entry['vsize'] + mallet_package_parent_rbf_entry['vsize'] + sweep_entry['vsize']

        mary_block_template_fees = alice_parent_entry['fees']['base'] + mallet_package_parent_rbf_entry['fees']['base'] + sweep_entry['fees']['base']
        mallet_block_template_fees = alice_parent_entry['fees']['base'] + alice_first_rbf_entry['fees']['base'] + mallet_package_parent_rbf_entry['fees']['base'] + sweep_entry['fees']['base']

        self.log.info("Mary Block Template Vsize {} Fees {}".format(mary_block_template_vsize, mary_block_template_fees))
        self.log.info("Mallet Block Template Vsize {} Fees {}".format(mallet_block_template_vsize, mallet_block_template_fees))

        # SHOULD HIT : "package RBF checks passed" in the logs
        #assert_equal(True, False) 

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_replacement_cycling_timing_cluster()

if __name__ == '__main__':
    ReplacementCyclingTimingClusterTest(__file__).main()
