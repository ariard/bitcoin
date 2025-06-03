#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.blocktools import (
    create_coinbase,
    get_witness_script,
    NORMAL_GBT_REQUEST_PARAMS,
    TIME_GENESIS_BLOCK,
)

from test_framework.messages import (
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    COutPoint,
    sha256,
    COIN,
)

from test_framework.script import (
    CScript,
    OP_TRUE,
    OP_0,
    OP_IF,
    OP_ELSE,
    OP_CHECKSIG,
    OP_CHECKMULTISIG,
    OP_ENDIF,
)

from test_framework.util import (
    assert_equal,
)

from test_framework.test_framework import BitcoinTestFramework

from test_framework.wallet import MiniWallet

OVERFLOW_SCRIPT = CScript([OP_IF,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, 
        OP_ELSE,
        OP_TRUE,
        OP_ENDIF])

LIMITED_OVERFLOW_SCRIPT = CScript([OP_IF,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG,
        OP_CHECKMULTISIG, OP_CHECKMULTISIG, OP_CHECKMULTISIG, 
        OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG,
        OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG,
        OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG,
        OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG,
        OP_CHECKSIG, OP_CHECKSIG, OP_CHECKSIG, 
        OP_ELSE,
        OP_TRUE,
        OP_ENDIF])

def generate_overflow_parent_tx(wallet, coin, input_amount, sat_per_vbyte, nsequence):

    overflow_script = OVERFLOW_SCRIPT
    overflow_scriptpubkey = CScript([OP_0, sha256(overflow_script)])

    parent_overflow_tx_fee = 200 * sat_per_vbyte
    parent_overflow_tx = CTransaction()
    parent_overflow_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nsequence))

    parent_overflow_tx.vout.append(CTxOut(int(input_amount - parent_overflow_tx_fee), overflow_scriptpubkey))
    parent_overflow_tx.rehash()

    wallet.sign_tx(parent_overflow_tx)
    return parent_overflow_tx

def generate_overflow_parent_tx_limited(wallet, coin, input_amount, sat_per_vbyte, nsequence):

    overflow_script = LIMITED_OVERFLOW_SCRIPT
    overflow_scriptpubkey = CScript([OP_0, sha256(overflow_script)])

    parent_overflow_tx_fee = 200 * sat_per_vbyte
    parent_overflow_tx = CTransaction()
    parent_overflow_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nsequence))

    parent_overflow_tx.vout.append(CTxOut(int(input_amount - parent_overflow_tx_fee), overflow_scriptpubkey))
    parent_overflow_tx.rehash()

    wallet.sign_tx(parent_overflow_tx)
    return parent_overflow_tx

def generate_test_parent_tx(wallet, coin, input_amount, sat_per_vbyte, nsequence):

    test_parent_script = CScript([OP_IF, OP_CHECKSIG, OP_ELSE, OP_TRUE, OP_ENDIF])
    test_parent_scriptpubkey = CScript([OP_0, sha256(test_parent_script)])

    test_parent_tx_fee = 200 * sat_per_vbyte
    test_parent_tx = CTransaction()
    test_parent_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b"", nsequence))

    test_parent_tx.vout.append(CTxOut(int(input_amount - test_parent_tx_fee), test_parent_scriptpubkey))
    test_parent_tx.rehash()

    wallet.sign_tx(test_parent_tx)
    return test_parent_tx

def generate_overflow_tx(parent_txid, parent_vout, input_amount, sat_per_vbyte, nsequence):

    exit_script = CScript([OP_TRUE])
    exit_scriptpubkey = CScript([OP_0, sha256(exit_script)])

    redeem_script = OVERFLOW_SCRIPT

    overflow_tx_fee = 19800 * sat_per_vbyte

    overflow_tx = CTransaction()
    overflow_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), parent_vout), b"", nsequence))
    overflow_tx.vout.append(CTxOut(int(input_amount - overflow_tx_fee), exit_scriptpubkey))

    overflow_tx.wit.vtxinwit.append(CTxInWitness())
    overflow_tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([]), redeem_script]

    overflow_tx.rehash()
    return overflow_tx

def generate_overflow_tx_limited(parent_txid, parent_vout, input_amount, sat_per_vbyte, nsequence):

    exit_script = CScript([OP_TRUE])
    exit_scriptpubkey = CScript([OP_0, sha256(exit_script)])

    redeem_script = LIMITED_OVERFLOW_SCRIPT

    overflow_tx_fee = 1995 * sat_per_vbyte

    overflow_tx = CTransaction()
    overflow_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), parent_vout), b"", nsequence))
    overflow_tx.vout.append(CTxOut(int(input_amount - overflow_tx_fee), exit_scriptpubkey))

    overflow_tx.wit.vtxinwit.append(CTxInWitness())
    overflow_tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([]), redeem_script]

    overflow_tx.rehash()
    return overflow_tx

def generate_test_tx(parent_txid, parent_vout, input_amount, sat_per_vbyte, nsequence):

    exit_script = CScript([OP_TRUE])
    exit_scriptpubkey = CScript([OP_0, sha256(exit_script)])

    redeem_script = CScript([OP_IF, OP_CHECKSIG, OP_ELSE, OP_TRUE, OP_ENDIF])

    test_tx_fee = 97 * sat_per_vbyte

    test_tx = CTransaction()
    test_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), parent_vout), b"", nsequence))
    test_tx.vout.append(CTxOut(int(input_amount - test_tx_fee), exit_scriptpubkey))

    test_tx.wit.vtxinwit.append(CTxInWitness())
    test_tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([]), redeem_script]

    test_tx.rehash()
    return test_tx

class BlockOpsigOverflowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
   
    def test_block_opsig_overflow(self):

        alice = self.nodes[0]

        self.generate(alice, 501)

        coins_collection = []
        for i in range(0, 20):
            coins_collection.append(self.wallet.get_utxo())

        # This should be a different overflow script
        overflow_coin_21 = self.wallet.get_utxo()

        # We generate parent overflow transaction to reach the 80k block limit
        overflow_parent_txn = []
        for coin in coins_collection:
            overflow_parent_txn.append(generate_overflow_parent_tx(self.wallet, coin, coin['value'] * COIN, 1, 0))

        # This should be a different overflow script
        overflow_parent_tx_21 = generate_overflow_parent_tx_limited(self.wallet, overflow_coin_21, overflow_coin_21['value'] * COIN, 1, 0)

        # Forward all the parent transactions
        overflow_parent_txids = []
        for tx in overflow_parent_txn:
            overflow_parent_txids.append(alice.sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0))

        overflow_parent_txid_21 = alice.sendrawtransaction(hexstring=overflow_parent_tx_21.serialize().hex(), maxfeerate=0)

        assert_equal(21, len(alice.getrawmempool()))

        test_coin = self.wallet.get_utxo()

        test_parent_tx = generate_test_parent_tx(self.wallet, test_coin, test_coin['value'] * COIN, 1, 0)

        test_parent_txid = alice.sendrawtransaction(hexstring=test_parent_tx.serialize().hex(), maxfeerate=0)

        self.generate(alice, 1)

        assert_equal(0, len(alice.getrawmempool()))

        self.log.info("21 Parent txn overflow confirmed + 1 Test Parent 1")

        # Generate the opsig overflow txn
        overflow_txn = []
        for txid in overflow_parent_txids:
            # the overflow parent tx 20 should be switched to each exact parent,
            # change nothings as the value should be the same for each child
            overflow_txn.append(generate_overflow_tx(txid, 0, overflow_parent_tx_21.vout[0].nValue, 2, 0))

        overflow_tx_21 = generate_overflow_tx_limited(overflow_parent_txid_21, 0, overflow_parent_tx_21.vout[0].nValue, 2, 0)

        # Broadcast all overflow txn in the mempool
        for tx in overflow_txn:
           alice.sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0) 
     
        overflow_txid_21 = alice.sendrawtransaction(hexstring=overflow_tx_21.serialize().hex(), maxfeerate=0)

        assert_equal(21, len(alice.getrawmempool()))

        test_tx = generate_test_tx(test_parent_txid, 0, test_parent_tx.vout[0].nValue, 1, 0)

        test_txid = alice.sendrawtransaction(hexstring=test_tx.serialize().hex(), maxfeerate=0)

        mempool_txn = alice.getrawmempool()

        #for tx in mempool_txn:
        #    self.log.info("Mempool entry {}".format(alice.getmempoolentry(tx)))
        self.log.info("Mempool entry {}".format(alice.getmempoolentry(mempool_txn[0])))
    
        self.log.info("Mempool len {}".format(len(mempool_txn)))

        self.log.info("Twenty overflow txn in mempools + 1 Test tx")

        block_template = alice.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        txn = block_template['transactions']
        block_sigops = 0
        block_fee = 0
        block_weight = 0
        i = 0
        for tx in txn:
            self.log.info("tx indice {} sigops {} fee {} weight {}".format(i, tx['sigops'], tx['fee'], tx['weight']))
            block_sigops += tx['sigops']
            block_fee += tx['fee']
            block_weight += tx['weight']
            i += 1

        self.log.info("block sigops {}".format(block_sigops))
        self.log.info("block fee {}".format(block_fee))
        self.log.info("block weight {}".format(block_weight))

        self.generate(alice, 1)

        assert_equal(1, len(alice.getrawmempool()))
        assert test_txid in alice.getrawmempool()

        self.log.info("Alice's block template can be junked with sigops-full txn")
        self.log.info("If the test tx is a commitment tx, the confirmation is delayed by 1 block")

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_block_opsig_overflow()

if __name__ == '__main__':
    BlockOpsigOverflowTest(__file__).main()
