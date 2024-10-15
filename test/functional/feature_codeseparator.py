#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test OP_CODESEPARATOR"""

import time

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_coinbase,
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)

from test_framework.messages import (
        CBlock,
        CTransaction,
        CTxIn,
        CTxOut,
        COutPoint,
        COIN,
        sha256,
)

from test_framework.script import (
    CScript,
    OP_0,
    OP_TRUE,
    OP_FALSE,
    OP_CHECKSIG,
    OP_NOP,
    OP_CODESEPARATOR,
    LegacySignatureHash,
    SIGHASH_ALL,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import getnewdestination
from test_framework.wallet_util import generate_keypair

from test_framework.key import (
        ECKey,
        ECPubKey
)

def generate_parent_tx(funder_node, txid):

    # anyone can spend script
    script_pubkey = CScript([])

    parent_tx = CTransaction()
    # assume we spend index 0
    parent_tx.vin.append(CTxIn(COutPoint(int(txid, 16), 0), b""))
    parent_tx.vout.append(CTxOut(int(9.99998 * COIN), script_pubkey))
    parent_tx.rehash()

    parent_signed = funder_node.signrawtransactionwithkey(parent_tx.serialize().hex(), [funder_node.get_deterministic_priv_key().key])['hex']
    return parent_signed

def generate_spend_tx(funder_node, parent_txid, alice_pubkey, alice_seckey):

    script_code = CScript([OP_CHECKSIG])

    spend_tx_scriptpubkey = CScript([OP_TRUE])

    # first - generate a transaction with the scriptCode committed

    spend_tx_one = CTransaction()
    # we put as scriptSig the scriptCode
    spend_tx_one.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 0), scriptSig=script_code, nSequence=0))
    # account 2000 for fee
    spend_tx_one.vout.append(CTxOut(int(9.99998 * COIN - 2000), spend_tx_scriptpubkey))

    # second - generate a sighash with the transaction with the scriptCode only committed

    (sighash, err) = LegacySignatureHash(script_code, spend_tx_one, 0, SIGHASH_ALL)

    assert err is None

    der_sig = alice_seckey.sign_ecdsa(sighash, low_s=True, rfc6979=True)

    # check quickly if DER-encoded sig.
    assert_equal(der_sig[0], 0x30)

    # third - we update the transaction scriptSig with generated der_sig and separator script

    full_script = CScript([der_sig + bytes([SIGHASH_ALL]), alice_pubkey.get_bytes(), OP_CODESEPARATOR, OP_CHECKSIG])
 
    spend_tx_two = CTransaction()
    spend_tx_two.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 0), scriptSig=full_script, nSequence=0))
    spend_tx_two.vout.append(CTxOut(int(9.99998 * COIN - 2000), spend_tx_scriptpubkey))

    spend_tx_two.rehash()

    return spend_tx_two

class CodeseparatorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[
            '-addresstype=legacy',
            '-acceptnonstdtxn=1',
            '-par=1',  # Use only one script thread to get the exact reject reason for testing
        ], [
            '-addresstype=legacy',
            '-acceptnonstdtxn=1',
            '-par=1',  # Use only one script thread to get the exact reject reason for testing
        ]]

    def run_test(self):

        alice = self.nodes[0]

        bob = self.nodes[1]

        ret = self.generatetoaddress(alice, 1, alice.get_deterministic_priv_key().address)

        block = alice.getblock(alice.getbestblockhash(), verbosity=2)
        block_txids = [tx['txid'] for tx in block['tx']]

        # mature the transaction for spending
        self.generatetoaddress(alice, 100, alice.get_deterministic_priv_key().address)
        self.sync_all()

        alice_seckey = ECKey()
        alice_seckey.generate()

        parent_tx = generate_parent_tx(alice, block_txids[0])
        parent_txid = alice.sendrawtransaction(hexstring=parent_tx, maxfeerate=0)

        self.log.info('Parent transaction broadcast')

        assert parent_txid in alice.getrawmempool()

        # we mine the parent transaction
        self.generatetoaddress(alice, 1, alice.get_deterministic_priv_key().address)
        self.sync_all()

        assert parent_txid not in alice.getrawmempool()

        self.log.info('Spend transaction generate')

        spend_tx = generate_spend_tx(alice, parent_txid, alice_seckey.get_pubkey(), alice_seckey)

        self.log.info("Spend transaction has been generated")

        self.disconnect_nodes(0, 1)
        self.sync_all()

        # we fail on SCRIPT_VERIFY_CONST_SCRIPTCODE, we'll bypass it by building a block directly.
        #assert_raises_rpc_error(-26, "non-mandatory-script-verify-flag (Using OP_CODESEPARATOR in non-witness script)", alice.sendrawtransaction, spend_tx.serialize().hex(), 0)

        # check that alice and bob same block height / block hash
        alice_block = alice.getblock(alice.getbestblockhash(), verbosity=2)
        bob_block = bob.getblock(bob.getbestblockhash(), verbosity=2)
        assert_equal(alice_block, bob_block)

        self.log.info("Alice and Bob same chain tip height / block")

        # now, bob generate a block template
        template = bob.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        tx_list = [spend_tx.serialize().hex()]
        coinbase = create_coinbase(height=int(template["height"]))
        block = create_block(hashprev=int(bob.getbestblockhash(), 16), coinbase=coinbase, ntime= template["curtime"], txlist=tx_list)
        block.solve()

        ret = bob.submitblock(hexdata=block.serialize().hex())
 
        alice_block = alice.getblock(alice.getbestblockhash(), verbosity=1)
        bob_block = bob.getblock(bob.getbestblockhash(), verbosity=1)

        assert_equal(alice_block['height'], 102)
        assert_equal(bob_block['height'], 103)

        # we check that the spend transaction with the OP_CODESEPARATOR been included
        assert_raises_rpc_error(-27, "Transaction already in block chain", bob.sendrawtransaction, spend_tx.serialize().hex(), 0)

        self.log.info("Spend transaction has been included in the blockchain")

        assert_equal(False, True)


if __name__ == '__main__':
    CodeseparatorTest().main()
