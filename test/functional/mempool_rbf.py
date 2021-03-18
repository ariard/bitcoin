#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
        assert_equal,
        assert_raises_rpc_error,
)

class MempoolRBF(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # Send tx from which to conflict outputs later
        base_txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("10"))
        self.nodes[0].generate(1)
        self.sync_blocks()

        # Create txn, with conflicted txn spending outpoint A & B, A is going to be spent by conflicting_tx_A and B is going to be spent by conflicting_tx_B
        optin_parent_tx = self.nodes[0].createrawtransaction([{
            'txid': base_txid,
            'vout': 0,
            "sequence": 0xfffffffd,
        }], {self.nodes[0].getnewaddress(): Decimal("9.99998")})

        optin_parent_tx = self.nodes[0].signrawtransactionwithwallet(optin_parent_tx)

        ## Broadcast parent tx
        optin_parent_txid = self.nodes[0].sendrawtransaction(hexstring=optin_parent_tx["hex"], maxfeerate=0)
        assert optin_parent_txid in self.nodes[0].getrawmempool()

        replacement_parent_tx = self.nodes[0].createrawtransaction([{
            'txid': base_txid,
            'vout': 0,
            "sequence": 0xfffffffd,
        }], {self.nodes[0].getnewaddress(): Decimal("9.90000")})

        replacement_parent_tx = self.nodes[0].signrawtransactionwithwallet(replacement_parent_tx)

        # Test if parent tx can be replaced.
        res = self.nodes[2].testmempoolaccept(rawtxs=[replacement_parent_tx['hex']], maxfeerate=0)[0]

        # Parent can be replaced.
        assert_equal(res['allowed'], True)

        optout_child_tx = self.nodes[0].createrawtransaction([{
            'txid': optin_parent_txid,
            'vout': 0,
            "sequence": 0xffffffff,
        }], {self.nodes[0].getnewaddress(): Decimal("9.99990")})

        optout_child_tx = self.nodes[0].signrawtransactionwithwallet(optout_child_tx)

        # Broadcast child tx
        optout_child_txid = self.nodes[0].sendrawtransaction(hexstring=optout_child_tx["hex"], maxfeerate=0)
        assert optout_child_txid in self.nodes[0].getrawmempool()

        replacement_child_tx = self.nodes[0].createrawtransaction([{
            'txid': optin_parent_txid,
            'vout': 0,
            "sequence": 0xffffffff,
        }], {self.nodes[0].getnewaddress(): Decimal("9.00000")})

        replacement_child_tx = self.nodes[0].signrawtransactionwithwallet(replacement_child_tx)

        # Broadcast replacement child tx
        # BIP 125 :
        # 1. The original transactions signal replaceability explicitly or through inheritance as described in the above
        # Summary section.
        # The original transaction (`optout_child_tx`) doesn't signal RBF but its parent (`optin_parent_txid`) does.
        # The replacement transaction (`replacement_child_tx`) should be able to replace the original transaction.
        assert optin_parent_txid in self.nodes[0].getrawmempool()
        assert_raises_rpc_error(-26, 'txn-mempool-conflict', self.nodes[0].sendrawtransaction, replacement_child_tx["hex"], 0)

if __name__ == '__main__':
    MempoolRBF().main()
