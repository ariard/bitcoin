#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining RPCs

- getmininginfo
- getblocktemplate proposal mode
- submitblock"""

import copy
import time
from decimal import Decimal

from test_framework.blocktools import (
    create_coinbase,
    get_witness_script,
    NORMAL_GBT_REQUEST_PARAMS,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import (
    BLOCK_HEADER_SIZE,
    CBlock,
    CBlockHeader,
    COIN,
    ser_uint256,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    get_fee,
)
from test_framework.wallet import MiniWallet

from test_framework.authproxy import JSONRPCException

# CMainParams nPowTargetTimespan / nPowTargetSpacing
CONSENSUS_DIFFICULTY_ADJUSTEMENT_INTERVAL = 2016

DIFFICULTY_ADJUSTMENT_INTERVAL = 144
MAX_FUTURE_BLOCK_TIME = 2 * 3600
MAX_TIMEWARP = 600
VERSIONBITS_TOP_BITS = 0x20000000
VERSIONBITS_DEPLOYMENT_TESTDUMMY_BIT = 28
DEFAULT_BLOCK_MIN_TX_FEE = 1000  # default `-blockmintxfee` setting [sat/kvB]


def assert_template(node, block, expect, rehash=True):
    if rehash:
        block.hashMerkleRoot = block.calc_merkle_root()
    rsp = node.getblocktemplate(template_request={
        'data': block.serialize().hex(),
        'mode': 'proposal',
        'rules': ['segwit'],
    })
    assert_equal(rsp, expect)


class MiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.supports_cli = False

    def mine_chain(self):
        self.log.info('Create some old blocks')
        for t in range(TIME_GENESIS_BLOCK, TIME_GENESIS_BLOCK + 200 * 600, 600):
            self.nodes[0].setmocktime(t)
            self.generate(self.wallet, 1, sync_fun=self.no_op)
        mining_info = self.nodes[0].getmininginfo()
        assert_equal(mining_info['blocks'], 200)
        assert_equal(mining_info['currentblocktx'], 0)
        assert_equal(mining_info['currentblockweight'], 4000)

        self.log.info('test blockversion')
        self.restart_node(0, extra_args=[f'-mocktime={t}', '-blockversion=1337'])
        self.connect_nodes(0, 1)
        assert_equal(1337, self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)['version'])
        self.restart_node(0, extra_args=[f'-mocktime={t}'])
        self.connect_nodes(0, 1)
        assert_equal(VERSIONBITS_TOP_BITS + (1 << VERSIONBITS_DEPLOYMENT_TESTDUMMY_BIT), self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)['version'])
        self.restart_node(0)
        self.connect_nodes(0, 1)

    def test_blockmintxfee_parameter(self):
        self.log.info("Test -blockmintxfee setting")
        self.restart_node(0, extra_args=['-minrelaytxfee=0', '-persistmempool=0'])
        node = self.nodes[0]

        # test default (no parameter), zero and a bunch of arbitrary blockmintxfee rates [sat/kvB]
        for blockmintxfee_sat_kvb in (DEFAULT_BLOCK_MIN_TX_FEE, 0, 50, 100, 500, 2500, 5000, 21000, 333333, 2500000):
            blockmintxfee_btc_kvb = blockmintxfee_sat_kvb / Decimal(COIN)
            if blockmintxfee_sat_kvb == DEFAULT_BLOCK_MIN_TX_FEE:
                self.log.info(f"-> Default -blockmintxfee setting ({blockmintxfee_sat_kvb} sat/kvB)...")
            else:
                blockmintxfee_parameter = f"-blockmintxfee={blockmintxfee_btc_kvb:.8f}"
                self.log.info(f"-> Test {blockmintxfee_parameter} ({blockmintxfee_sat_kvb} sat/kvB)...")
                self.restart_node(0, extra_args=[blockmintxfee_parameter, '-minrelaytxfee=0', '-persistmempool=0'])
                self.wallet.rescan_utxos()  # to avoid spending outputs of txs that are not in mempool anymore after restart

            # submit one tx with exactly the blockmintxfee rate, and one slightly below
            tx_with_min_feerate = self.wallet.send_self_transfer(from_node=node, fee_rate=blockmintxfee_btc_kvb)
            assert_equal(tx_with_min_feerate["fee"], get_fee(tx_with_min_feerate["tx"].get_vsize(), blockmintxfee_btc_kvb))
            if blockmintxfee_btc_kvb > 0:
                lowerfee_btc_kvb = blockmintxfee_btc_kvb - Decimal(10)/COIN  # 0.01 sat/vbyte lower
                tx_below_min_feerate = self.wallet.send_self_transfer(from_node=node, fee_rate=lowerfee_btc_kvb)
                assert_equal(tx_below_min_feerate["fee"], get_fee(tx_below_min_feerate["tx"].get_vsize(), lowerfee_btc_kvb))
            else:  # go below zero fee by using modified fees
                tx_below_min_feerate = self.wallet.send_self_transfer(from_node=node, fee_rate=blockmintxfee_btc_kvb)
                node.prioritisetransaction(tx_below_min_feerate["txid"], 0, -1)

            # check that tx below specified fee-rate is neither in template nor in the actual block
            block_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
            block_template_txids = [tx['txid'] for tx in block_template['transactions']]
            self.generate(self.wallet, 1, sync_fun=self.no_op)
            block = node.getblock(node.getbestblockhash(), verbosity=2)
            block_txids = [tx['txid'] for tx in block['tx']]

            assert tx_with_min_feerate['txid'] in block_template_txids
            assert tx_with_min_feerate['txid'] in block_txids
            assert tx_below_min_feerate['txid'] not in block_template_txids
            assert tx_below_min_feerate['txid'] not in block_txids

    def test_timewarp(self):
        self.log.info("Test timewarp attack mitigation (BIP94)")
        node = self.nodes[0]

        self.log.info("Mine until the penultimate block of the retarget period")
        blockchain_info = self.nodes[0].getblockchaininfo()
        n = DIFFICULTY_ADJUSTMENT_INTERVAL - blockchain_info['blocks'] % DIFFICULTY_ADJUSTMENT_INTERVAL - 2
        t = blockchain_info['time']

        for _ in range(n):
            t += 600
            self.nodes[0].setmocktime(t)
            self.generate(self.wallet, 1, sync_fun=self.no_op)

        self.log.info("Create block two hours in the future")
        self.nodes[0].setmocktime(t + MAX_FUTURE_BLOCK_TIME)
        self.generate(self.wallet, 1, sync_fun=self.no_op)
        assert_equal(node.getblock(node.getbestblockhash())['time'], t + MAX_FUTURE_BLOCK_TIME)

        self.log.info("First block template of retarget period can't use wall clock time")
        self.nodes[0].setmocktime(t)
        # The template will have an adjusted timestamp, which we then modify
        tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_greater_than_or_equal(tmpl['curtime'], t + MAX_FUTURE_BLOCK_TIME - MAX_TIMEWARP)

        block = CBlock()
        block.nVersion = tmpl["version"]
        block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        block.nTime = tmpl["curtime"]
        block.nBits = int(tmpl["bits"], 16)
        block.nNonce = 0
        block.vtx = [create_coinbase(height=int(tmpl["height"]))]
        block.solve()
        assert_template(node, block, None)

        bad_block = copy.deepcopy(block)
        bad_block.nTime = t
        bad_block.solve()
        assert_raises_rpc_error(-25, 'time-timewarp-attack', lambda: node.submitheader(hexdata=CBlockHeader(bad_block).serialize().hex()))

    def test_break_timewarp_fix(self):

        # By default BitcoinTestFramework runs on regtest, with "self.chain: str = 'regtest'"
        # Note: for this test we modified CRegTestParams's `nPowTargetTimespan` and `nMinerConfirmationWindow`
        # to scale them on the `CMainParams` ones while keeping regtest `nPowTargetSpacing` unmodified. This
        # shall let reproduce the test independently with minimal difficulty blocks.

        self.log.info("Test timewarp attack mitigation")
        alice = self.nodes[0]
        bob = self.nodes[1]  # Bob is a non-upgraded mining node.
        caroll = self.nodes[2]

        # We disconnect Caroll
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(1, 2)
 
        # We check that best seen block by all network nodes is thegenesis block.
        assert_equal(alice.getbestblockhash(), bob.getblockhash(0))
        assert_equal(caroll.getbestblockhash(), bob.getblockhash(0))

        # We initialize all node clocks with the latest mined block.
        # See NodeClock::now() in src/util/time.cpp
        initial_time = self.nodes[0].getblockchaininfo()['time']
        alice.setmocktime(initial_time)
        bob.setmocktime(initial_time)
        caroll.setmocktime(initial_time)

        self.log.info("Alice node time %d", alice.mocktime)
        self.log.info("Bob node time %d", bob.mocktime)
        self.log.info("Caroll node time %d", caroll.mocktime)

        self.log.info("Alice tip block height %d", alice.getblockcount())
        self.log.info("Bob tip block height %d", bob.getblockcount())
        self.log.info("Caroll tip block height %d", caroll.getblockcount())

        alice_time = alice.getblockchaininfo()["time"]
        bob_time = bob.getblockchaininfo()["time"]
        caroll_time = caroll.getblockchaininfo()["time"]

        self.log.info("Alice tip block time %d", alice_time)
        self.log.info("Bob tip block time %d", bob_time)
        self.log.info("Caroll tip block time %d", caroll_time)

        self.log.info("Alice mines until the last block of the current retarget period")
        # We advance from block 212 to block 1802 the last block before the retarget period block.
        blockchain_info = self.nodes[0].getblockchaininfo()
        block_until_next_retarget_period_minus_one = CONSENSUS_DIFFICULTY_ADJUSTEMENT_INTERVAL - blockchain_info['blocks'] % CONSENSUS_DIFFICULTY_ADJUSTEMENT_INTERVAL - 2
        assert_equal(block_until_next_retarget_period_minus_one, 2014)

        alice_time = alice.getblockchaininfo()["time"]
        bob_time = bob.getblockchaininfo()["time"]
        caroll_time = caroll.getblockchaininfo()["time"]
  
        # We advance the clock of alice and bob in a synchronized fashion
        # even if alice generate all the blocks.
        for i in range(block_until_next_retarget_period_minus_one):
            alice_time += 600
            bob_time += 600
            caroll_time += 600
            alice.setmocktime(alice_time)
            bob.setmocktime(bob_time)
            # We keep Caroll updated with network time, even if it doesn't
            # receive the chain of blocks for now.
            caroll.setmocktime(caroll_time)
            self.generate(alice, 1, sync_fun=self.no_op)

        stop_time = time.time() + 60
        while time.time() <= stop_time:
            bob_tip_height = bob.getblockcount()
            self.log.info("Bob Height: %d", bob_tip_height)

            if bob_tip_height == 2014:
                break;
    
            time.sleep(1)

        # We check both Alice and Bob are in height / time sync.
        # Alice and Bob height should be 2014 / 2014.
        assert_equal(alice.getblockcount(), bob.getblockcount())
        assert_equal(alice.getblockchaininfo()["time"], bob.getblockchaininfo()["time"])

        alice_time = alice.getblockchaininfo()["time"]
        bob_time = bob.getblockchaininfo()["time"]
        caroll_time = caroll.getblockchaininfo()["time"]

        self.log.info("Alice node time %d tip block height %d tip block time %d", alice.mocktime, alice.getblockcount(), alice_time)
        self.log.info("Bob node time %d tip block height %d tip block time %d", bob.mocktime, bob.getblockcount(), bob_time)
        self.log.info("Caroll node time %d tip block height %d tip block time %d", caroll.mocktime, caroll.getblockcount(), caroll_time)

        self.log.info("Alice mines the penultimate block one hour in the future")
        alice.setmocktime(alice_time + 3600)
        self.generate(alice, 1, sync_fun=self.no_op)
        # We scaled back Alice node local time, as it was just to generate the offsetting block
        alice.setmocktime(alice_time)

        stop_time = time.time() + 60
        while time.time() <= stop_time:
            alice_tip_height = alice.getblockcount()
            bob_tip_height = bob.getblockcount()
            self.log.info("Alice Height: %d", bob_tip_height)
            self.log.info("Bob Height: %d", bob_tip_height)

            if alice_tip_height == bob_tip_height:
                break;

            time.sleep(1)

        assert_equal(alice.getblockcount(), bob.getblockcount())
        assert_equal(alice.getblockcount(), 2015)
        assert_equal(alice.getblock(alice.getbestblockhash()), bob.getblock(bob.getbestblockhash()))

        # # We check that Alice tip block time is inferior to Bob node time
        # alice_tip_block_time = alice.getblockchaininfo()["time"]
        # assert_greater_than(bob.mocktime, alice_tip_block_time)

        self.log.info("Bob validated Alice's penultimate block")

        penultimate_block_time = alice.getblock(alice.getbestblockhash())['time']
        penultimate_block_hash = alice.getbestblockhash()

        self.log.info("Penultimate Block (time %d / hash %s)", penultimate_block_time, str(penultimate_block_hash))

        alice_time = alice.getblockchaininfo()["time"]
        bob_time = bob.getblockchaininfo()["time"]
        caroll_time = caroll.getblockchaininfo()["time"]

        self.log.info("Alice node time %d tip block height %d tip block time %d", alice.mocktime, alice.getblockcount(), alice_time)
        self.log.info("Bob node time %d tip block height %d tip block time %d", bob.mocktime, bob.getblockcount(), bob_time)
        self.log.info("Caroll node time %d tip block height %d tip block time %d", caroll.mocktime, caroll.getblockcount(), caroll_time)

        alice_bob_time_dilation = alice_time - bob.mocktime
        self.log.info("Alice tip block time Bob node time Time Dilation %d (local clocks synced on block 0 as common frame)", alice_bob_time_dilation)
        alice_caroll_time_dilation = alice_time - caroll.mocktime
        self.log.info("Alice tip blocktime Caroll node time Time Dilation %d (local clocks synced on block 0 as common frame)", alice_caroll_time_dilation)

        assert_equal(alice_bob_time_dilation, 3600)
        assert_equal(alice_caroll_time_dilation, 3600)

        # We disconnect Alice and Bob as network peers.
        self.disconnect_nodes(0, 1)

        self.log.info("Bob time is now %d", bob.mocktime)

        # We generate Bob block at height 2016...and Bob should fail so.
        try:
            self.generate(bob, 1, sync_fun=self.no_op)
        except JSONRPCException as json_error:
            self.log.info("Bob unable to generate new valid block")
            # We check we got the error from ContextualCheckBlockHeader()
            if json_error.error["code"] != -1:
                raise AssertionError("Unexpected JSONRPC error code %i" % json_error.error["code"])
            if "time-timewarp-attack" not in json_error.error['message']:
                raise AssertionError(
                    "Expected substring not found in error message:\nsubstring: '{}'\nerror message: '{}'.".format(
                        "time-timewarp-attack", json_error.error['message']))

        assert_equal(bob.getblockcount(), 2015)
        self.log.info("Bob chain height %d", bob.getblockcount())

        self.log.info("Alice node time %d tip block height %d tip block time %d", alice.mocktime, alice.getblockcount(), alice_time)
        self.log.info("Bob node time %d tip block height %d tip block time %d", bob.mocktime, bob.getblockcount(), bob_time)
        self.log.info("Caroll node time %d tip block height %d tip block time %d", caroll.mocktime, caroll.getblockcount(), caroll_time)

        # We re-connect and let Alice and Caroll block sync
        self.connect_nodes(0, 2)

        stop_time = time.time() + 60
        while time.time() <= stop_time:
            caroll_tip_height = caroll.getblockcount()
            self.log.info("Caroll Height: %d", caroll_tip_height)

            if caroll_tip_height == 2015:
                break;
    
            time.sleep(1)

        assert_equal(alice.getblockcount(), caroll.getblockcount())
 
        # We re-connect the whole network
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)

        alice_block_template = alice.getblocktemplate({"rules": ["segwit", "bip94"]})

        self.log.info("Tip block time %d, First block template retarget period %d", alice_time, alice_block_template['curtime'])

        block = CBlock()
        block.nVersion = alice_block_template["version"]
        block.hashPrevBlock = int(alice_block_template["previousblockhash"], 16)
        block.nTime = alice_block_template["curtime"]
        block.nBits = int(alice_block_template["bits"], 16)
        block.nNonce = 0
        block.vtx = [create_coinbase(height=int(alice_block_template["height"]))]
        block.solve()
        assert_template(alice, block, None)

        alice.submitblock(block.serialize().hex())
        assert_equal(alice.getblockcount(), 2016)
        assert_equal(alice.getblockcount(), bob.getblockcount())
        assert_equal(alice.getblockcount(), caroll.getblockcount())

        self.log.info("Alice node time %d tip block height %d tip block time %d", alice.mocktime, alice.getblockcount(), alice_time)
        self.log.info("Bob node time %d tip block height %d tip block time %d", bob.mocktime, bob.getblockcount(), bob_time)
        self.log.info("Caroll node time %d tip block height %d tip block time %d", caroll.mocktime, caroll.getblockcount(), caroll_time)




    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        #self.mine_chain()

        #def assert_submitblock(block, result_str_1, result_str_2=None):
        #    block.solve()
        #    result_str_2 = result_str_2 or 'duplicate-invalid'
        #    assert_equal(result_str_1, node.submitblock(hexdata=block.serialize().hex()))
        #    assert_equal(result_str_2, node.submitblock(hexdata=block.serialize().hex()))

        #self.log.info('getmininginfo')
        #mining_info = node.getmininginfo()
        #assert_equal(mining_info['blocks'], 200)
        #assert_equal(mining_info['chain'], self.chain)
        #assert 'currentblocktx' not in mining_info
        #assert 'currentblockweight' not in mining_info
        #assert_equal(mining_info['difficulty'], Decimal('4.656542373906925E-10'))
        #assert_equal(mining_info['networkhashps'], Decimal('0.003333333333333334'))
        #assert_equal(mining_info['pooledtx'], 0)

        #self.log.info("getblocktemplate: Test default witness commitment")
        #txid = int(self.wallet.send_self_transfer(from_node=node)['wtxid'], 16)
        #tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)

        ## Check that default_witness_commitment is present.
        #assert 'default_witness_commitment' in tmpl
        #witness_commitment = tmpl['default_witness_commitment']

        ## Check that default_witness_commitment is correct.
        #witness_root = CBlock.get_merkle_root([ser_uint256(0),
        #                                       ser_uint256(txid)])
        #script = get_witness_script(witness_root, 0)
        #assert_equal(witness_commitment, script.hex())

        ## Mine a block to leave initial block download and clear the mempool
        #self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        #tmpl = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        #self.log.info("getblocktemplate: Test capability advertised")
        #assert 'proposal' in tmpl['capabilities']
        #assert 'coinbasetxn' not in tmpl

        #next_height = int(tmpl["height"])
        #coinbase_tx = create_coinbase(height=next_height)
        ## sequence numbers must not be max for nLockTime to have effect
        #coinbase_tx.vin[0].nSequence = 2**32 - 2
        #coinbase_tx.rehash()

        #block = CBlock()
        #block.nVersion = tmpl["version"]
        #block.hashPrevBlock = int(tmpl["previousblockhash"], 16)
        #block.nTime = tmpl["curtime"]
        #block.nBits = int(tmpl["bits"], 16)
        #block.nNonce = 0
        #block.vtx = [coinbase_tx]

        #self.log.info("getblocktemplate: segwit rule must be set")
        #assert_raises_rpc_error(-8, "getblocktemplate must be called with the segwit rule set", node.getblocktemplate, {})

        #self.log.info("getblocktemplate: Test valid block")
        #assert_template(node, block, None)

        #self.log.info("submitblock: Test block decode failure")
        #assert_raises_rpc_error(-22, "Block decode failed", node.submitblock, block.serialize()[:-15].hex())

        #self.log.info("getblocktemplate: Test bad input hash for coinbase transaction")
        #bad_block = copy.deepcopy(block)
        #bad_block.vtx[0].vin[0].prevout.hash += 1
        #bad_block.vtx[0].rehash()
        #assert_template(node, bad_block, 'bad-cb-missing')

        #self.log.info("submitblock: Test invalid coinbase transaction")
        #assert_raises_rpc_error(-22, "Block does not start with a coinbase", node.submitblock, CBlock().serialize().hex())
        #assert_raises_rpc_error(-22, "Block does not start with a coinbase", node.submitblock, bad_block.serialize().hex())

        #self.log.info("getblocktemplate: Test truncated final transaction")
        #assert_raises_rpc_error(-22, "Block decode failed", node.getblocktemplate, {
        #    'data': block.serialize()[:-1].hex(),
        #    'mode': 'proposal',
        #    'rules': ['segwit'],
        #})

        #self.log.info("getblocktemplate: Test duplicate transaction")
        #bad_block = copy.deepcopy(block)
        #bad_block.vtx.append(bad_block.vtx[0])
        #assert_template(node, bad_block, 'bad-txns-duplicate')
        #assert_submitblock(bad_block, 'bad-txns-duplicate', 'bad-txns-duplicate')

        #self.log.info("getblocktemplate: Test invalid transaction")
        #bad_block = copy.deepcopy(block)
        #bad_tx = copy.deepcopy(bad_block.vtx[0])
        #bad_tx.vin[0].prevout.hash = 255
        #bad_tx.rehash()
        #bad_block.vtx.append(bad_tx)
        #assert_template(node, bad_block, 'bad-txns-inputs-missingorspent')
        #assert_submitblock(bad_block, 'bad-txns-inputs-missingorspent')

        #self.log.info("getblocktemplate: Test nonfinal transaction")
        #bad_block = copy.deepcopy(block)
        #bad_block.vtx[0].nLockTime = 2**32 - 1
        #bad_block.vtx[0].rehash()
        #assert_template(node, bad_block, 'bad-txns-nonfinal')
        #assert_submitblock(bad_block, 'bad-txns-nonfinal')

        #self.log.info("getblocktemplate: Test bad tx count")
        ## The tx count is immediately after the block header
        #bad_block_sn = bytearray(block.serialize())
        #assert_equal(bad_block_sn[BLOCK_HEADER_SIZE], 1)
        #bad_block_sn[BLOCK_HEADER_SIZE] += 1
        #assert_raises_rpc_error(-22, "Block decode failed", node.getblocktemplate, {
        #    'data': bad_block_sn.hex(),
        #    'mode': 'proposal',
        #    'rules': ['segwit'],
        #})

        #self.log.info("getblocktemplate: Test bad bits")
        #bad_block = copy.deepcopy(block)
        #bad_block.nBits = 469762303  # impossible in the real world
        #assert_template(node, bad_block, 'bad-diffbits')

        #self.log.info("getblocktemplate: Test bad merkle root")
        #bad_block = copy.deepcopy(block)
        #bad_block.hashMerkleRoot += 1
        #assert_template(node, bad_block, 'bad-txnmrklroot', False)
        #assert_submitblock(bad_block, 'bad-txnmrklroot', 'bad-txnmrklroot')

        #self.log.info("getblocktemplate: Test bad timestamps")
        #bad_block = copy.deepcopy(block)
        #bad_block.nTime = 2**32 - 1
        #assert_template(node, bad_block, 'time-too-new')
        #assert_submitblock(bad_block, 'time-too-new', 'time-too-new')
        #bad_block.nTime = 0
        #assert_template(node, bad_block, 'time-too-old')
        #assert_submitblock(bad_block, 'time-too-old', 'time-too-old')

        #self.log.info("getblocktemplate: Test not best block")
        #bad_block = copy.deepcopy(block)
        #bad_block.hashPrevBlock = 123
        #assert_template(node, bad_block, 'inconclusive-not-best-prevblk')
        #assert_submitblock(bad_block, 'prev-blk-not-found', 'prev-blk-not-found')

        #self.log.info('submitheader tests')
        #assert_raises_rpc_error(-22, 'Block header decode failed', lambda: node.submitheader(hexdata='xx' * BLOCK_HEADER_SIZE))
        #assert_raises_rpc_error(-22, 'Block header decode failed', lambda: node.submitheader(hexdata='ff' * (BLOCK_HEADER_SIZE-2)))
        #assert_raises_rpc_error(-25, 'Must submit previous header', lambda: node.submitheader(hexdata=super(CBlock, bad_block).serialize().hex()))

        #block.nTime += 1
        #block.solve()

        #def chain_tip(b_hash, *, status='headers-only', branchlen=1):
        #    return {'hash': b_hash, 'height': 202, 'branchlen': branchlen, 'status': status}

        #assert chain_tip(block.hash) not in node.getchaintips()
        #node.submitheader(hexdata=block.serialize().hex())
        #assert chain_tip(block.hash) in node.getchaintips()
        #node.submitheader(hexdata=CBlockHeader(block).serialize().hex())  # Noop
        #assert chain_tip(block.hash) in node.getchaintips()

        #bad_block_root = copy.deepcopy(block)
        #bad_block_root.hashMerkleRoot += 2
        #bad_block_root.solve()
        #assert chain_tip(bad_block_root.hash) not in node.getchaintips()
        #node.submitheader(hexdata=CBlockHeader(bad_block_root).serialize().hex())
        #assert chain_tip(bad_block_root.hash) in node.getchaintips()
        ## Should still reject invalid blocks, even if we have the header:
        #assert_equal(node.submitblock(hexdata=bad_block_root.serialize().hex()), 'bad-txnmrklroot')
        #assert_equal(node.submitblock(hexdata=bad_block_root.serialize().hex()), 'bad-txnmrklroot')
        #assert chain_tip(bad_block_root.hash) in node.getchaintips()
        ## We know the header for this invalid block, so should just return early without error:
        #node.submitheader(hexdata=CBlockHeader(bad_block_root).serialize().hex())
        #assert chain_tip(bad_block_root.hash) in node.getchaintips()

        #bad_block_lock = copy.deepcopy(block)
        #bad_block_lock.vtx[0].nLockTime = 2**32 - 1
        #bad_block_lock.vtx[0].rehash()
        #bad_block_lock.hashMerkleRoot = bad_block_lock.calc_merkle_root()
        #bad_block_lock.solve()
        #assert_equal(node.submitblock(hexdata=bad_block_lock.serialize().hex()), 'bad-txns-nonfinal')
        #assert_equal(node.submitblock(hexdata=bad_block_lock.serialize().hex()), 'duplicate-invalid')
        ## Build a "good" block on top of the submitted bad block
        #bad_block2 = copy.deepcopy(block)
        #bad_block2.hashPrevBlock = bad_block_lock.sha256
        #bad_block2.solve()
        #assert_raises_rpc_error(-25, 'bad-prevblk', lambda: node.submitheader(hexdata=CBlockHeader(bad_block2).serialize().hex()))

        ## Should reject invalid header right away
        #bad_block_time = copy.deepcopy(block)
        #bad_block_time.nTime = 1
        #bad_block_time.solve()
        #assert_raises_rpc_error(-25, 'time-too-old', lambda: node.submitheader(hexdata=CBlockHeader(bad_block_time).serialize().hex()))

        ## Should ask for the block from a p2p node, if they announce the header as well:
        #peer = node.add_p2p_connection(P2PDataStore())
        #peer.wait_for_getheaders(timeout=5, block_hash=block.hashPrevBlock)
        #peer.send_blocks_and_test(blocks=[block], node=node)
        ## Must be active now:
        #assert chain_tip(block.hash, status='active', branchlen=0) in node.getchaintips()

        ## Building a few blocks should give the same results
        #self.generatetoaddress(node, 10, node.get_deterministic_priv_key().address)
        #assert_raises_rpc_error(-25, 'time-too-old', lambda: node.submitheader(hexdata=CBlockHeader(bad_block_time).serialize().hex()))
        #assert_raises_rpc_error(-25, 'bad-prevblk', lambda: node.submitheader(hexdata=CBlockHeader(bad_block2).serialize().hex()))
        #node.submitheader(hexdata=CBlockHeader(block).serialize().hex())
        #node.submitheader(hexdata=CBlockHeader(bad_block_root).serialize().hex())
        #assert_equal(node.submitblock(hexdata=block.serialize().hex()), 'duplicate')  # valid

        #self.test_blockmintxfee_parameter()
        #self.test_timewarp()
        self.test_break_timewarp_fix()


if __name__ == '__main__':
    MiningTest(__file__).main()
