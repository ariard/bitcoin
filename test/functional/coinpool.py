#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test generation and spending of a Coinpool output"""

import struct

from test_framework.util import assert_raises_rpc_error

from test_framework.test_framework import BitcoinTestFramework

from test_framework.key import EllipticCurve, compute_xonly_pubkey, ECKey, generate_privkey, sign_schnorr, tweak_add_pubkey
from test_framework.messages import (
        CTransaction,
        CTxIn,
        CTxInWitness,
        CTxOut,
        COutPoint,
        COIN,
)

from test_framework.script import (
        hash160,
        CScript,
        CScriptNum,
        OP_0,
        OP_1,
        OP_CHECKSIG,
        OP_DROP,
        OP_MERKLESUB,
        OP_PUSHDATA1,
        OP_TRUE,
        SIGHASH_ANYPREVOUT,
        SIGHASH_GROUP,
        SIGHASH_GROUP_ANYPUBKEY,
        SIGHASH_GROUP_ANYAMOUNT,
        TaprootSignatureHash,
        taproot_construct,
        taproot_tree_helper
)

SECP256K1_FIELD_SIZE = 2**256 - 2**32 - 977
SECP256K1 = EllipticCurve(SECP256K1_FIELD_SIZE, 0, 7)

class CoinpoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-minrelaytxfee=0']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        coins = node.listunspent()

        self.log.info("Generate the setup phase for 4 pool participants...")

        # Generate the participants exit P2PKH scriptPubKey
        alice_exit_seckey = ECKey()
        alice_exit_seckey.generate(True)
        alice_exit_pubkey = alice_exit_seckey.get_pubkey()
        alice_exit_pubkeyhash = hash160(alice_exit_pubkey.get_bytes())
        alice_exit_scriptpubkey = CScript([OP_0, alice_exit_pubkeyhash])

        bob_exit_seckey = ECKey()
        bob_exit_seckey.generate(True)
        bob_exit_pubkey = bob_exit_seckey.get_pubkey()
        bob_exit_pubkeyhash = hash160(bob_exit_pubkey.get_bytes())
        bob_exit_scriptpubkey = CScript([OP_0, bob_exit_pubkeyhash])

        caroll_exit_seckey = ECKey()
        caroll_exit_seckey.generate(True)
        caroll_exit_pubkey = caroll_exit_seckey.get_pubkey()
        caroll_exit_pubkeyhash = hash160(caroll_exit_pubkey.get_bytes())
        caroll_exit_scriptpubkey = CScript([OP_0, caroll_exit_pubkeyhash])

        dave_exit_seckey = ECKey()
        dave_exit_seckey.generate(True)
        dave_exit_pubkey = dave_exit_seckey.get_pubkey()
        dave_exit_pubkeyhash = hash160(dave_exit_pubkey.get_bytes())
        dave_exit_scriptpubkey = CScript([OP_0, dave_exit_pubkeyhash])

        # Generate the participants pool points
        alice_pool_seckey = generate_privkey()
        alice_pool_pubkey = compute_xonly_pubkey(alice_pool_seckey)[0]

        bob_pool_seckey = generate_privkey()
        bob_pool_pubkey = compute_xonly_pubkey(bob_pool_seckey)[0]

        caroll_pool_seckey = generate_privkey()
        caroll_pool_pubkey = compute_xonly_pubkey(caroll_pool_seckey)[0]

        dave_pool_seckey = generate_privkey()
        dave_pool_pubkey = compute_xonly_pubkey(dave_pool_seckey)[0]

        # Aggregate contribution (unsafe!)
        xa = int.from_bytes(alice_pool_pubkey, 'big')
        Pa = SECP256K1.lift_x(xa)

        xb = int.from_bytes(bob_pool_pubkey, 'big')
        Pb = SECP256K1.lift_x(xb)

        xc = int.from_bytes(caroll_pool_pubkey, 'big')
        Pc = SECP256K1.lift_x(xc)

        xd = int.from_bytes(dave_pool_pubkey, 'big')
        Pd = SECP256K1.lift_x(xd)

        Pab = SECP256K1.add(Pa, Pb)
        Pabc = SECP256K1.add(Pab, Pc)
        Pabcd = SECP256K1.add(Pabc, Pd)

        pool_pubkey = SECP256K1.affine(Pabcd)
        if SECP256K1.has_even_y(pool_pubkey) == False:
            pool_pubkey = SECP256K1.negate(pool_pubkey)

        # Generate the participants amounts
        alice_amount = int(COIN / 10)

        bob_amount = int(COIN / 10 * 2)

        caroll_amount = int(COIN / 10 * 3)

        dave_amount = int(COIN / 10 * 4)

        # Generate the participants contract points
        alice_contract_seckey = ECKey()
        alice_contract_seckey.generate(True)
        alice_contract_pubkey = alice_contract_seckey.get_pubkey()

        bob_contract_seckey = ECKey()
        bob_contract_seckey.generate(True)
        bob_contract_pubkey = bob_contract_seckey.get_pubkey()

        caroll_contract_seckey = ECKey()
        caroll_contract_seckey.generate(True)
        caroll_contract_pubkey = caroll_contract_seckey.get_pubkey()

        dave_contract_seckey = ECKey()
        dave_contract_seckey.generate(True)
        dave_contract_pubkey = dave_contract_seckey.get_pubkey()

        # TODO: Musig2 aggregation P := sum_i u_i * P_i
        aggregated_contract_seckey = generate_privkey()
        aggregated_contract_pubkey = compute_xonly_pubkey(aggregated_contract_seckey)[0]

        # Generate the withdraw scripts
        alice_withdraw_tapscript = CScript([OP_1, alice_pool_pubkey, OP_MERKLESUB, OP_DROP, OP_DROP, int(1).to_bytes(1, 'big') + aggregated_contract_pubkey, OP_CHECKSIG])

        bob_withdraw_tapscript = CScript([OP_MERKLESUB, 1, bob_pool_pubkey, aggregated_contract_pubkey, OP_CHECKSIG])

        caroll_withdraw_tapscript = CScript([OP_MERKLESUB, 1, caroll_pool_pubkey, aggregated_contract_pubkey, OP_CHECKSIG])

        dave_withdraw_tapscript = CScript([OP_MERKLESUB, 1, dave_pool_pubkey, aggregated_contract_pubkey, OP_CHECKSIG])

        withdraw_tapscripts = [("s0", alice_withdraw_tapscript), ("s1", bob_withdraw_tapscript), ("s2", caroll_withdraw_tapscript), ("s3", dave_withdraw_tapscript)]

        # Generate the pool tree
        pool_tree = taproot_construct(pool_pubkey[0].to_bytes(32, 'big'), withdraw_tapscripts)

        # Generate the setup transaction
        coin = coins.pop() # Pick a random coin(base) to spend
        setup_tx = CTransaction()
        setup_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), 0), b"", 0xffffffff))
        setup_tx_output = CTxOut(int(COIN), pool_tree[0])
        setup_tx.vout.append(setup_tx_output)
        setup_tx.nLockTime = 0

        # Sign/broadcast the setup_tx
        raw_setup_tx = node.signrawtransactionwithwallet(setup_tx.serialize().hex())
        setup_txid = node.sendrawtransaction(hexstring=raw_setup_tx['hex'], maxfeerate=0)
        node.generate(1)
        assert setup_txid not in node.getrawmempool()

        # Generate the withdraw transactions
        alice_withdraw_tx = CTransaction()
        alice_withdraw_tx.vin.append(CTxIn(COutPoint(int(setup_txid, 16), 0), b"", 0xffffffff)) #TODO: can be mutated thanks to SIGHASH_ANYPREVOUT
        alice_withdraw_tx.vout.append(CTxOut(alice_amount, alice_exit_scriptpubkey))

        bob_withdraw_tx = CTransaction()
        bob_withdraw_tx.vin.append(CTxIn(COutPoint(int(setup_txid, 16), 0), b"", 0xffffffff)) #TODO: can be mutated thanks to SIGHASH_ANYPREVOUT
        bob_withdraw_tx.vout.append(CTxOut())
        bob_withdraw_tx.vout.append(CTxOut(bob_amount, bob_exit_scriptpubkey))

        caroll_withdraw_tx = CTransaction()
        caroll_withdraw_tx.vin.append(CTxIn(COutPoint(int(setup_txid, 16), 0), b"", 0xffffffff))
        caroll_withdraw_tx.vout.append(CTxOut())
        caroll_withdraw_tx.vout.append(CTxOut(caroll_amount, caroll_exit_scriptpubkey))

        dave_withdraw_tx = CTransaction()
        dave_withdraw_tx.vin.append(CTxIn(COutPoint(int(setup_txid, 16), 0), b"", 0xffffffff))
        dave_withdraw_tx.vout.append(CTxOut())
        dave_withdraw_tx.vout.append(CTxOut(dave_amount, dave_exit_scriptpubkey))

        #bob_withdraw_hashtype = SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_GROUP_ANYPUBKEY | SIGHASH_GROUP_ANYAMOUNT
        #bob_withdraw_hash = TaprootSignatureHash(bob_withdraw_tx, [setup_tx_output], bob_withdraw_hashtype, 0, True, script=bob_withdraw_tapscript, annex=None)
        #contract_sig = sign_schnorr(aggregated_contract_seckey, bob_withdraw_hash) #TODO: flip r ? flip p ?
        #bob_control_block = bytes([pool_tree[4]["s1"][1] + pool_tree[2]]) + pool_tree[1] + pool_tree[4]["s1"][2]
        #bob_withdraw_tx.wit.vtxinwit.append(CTxInWitness())
        #bob_withdraw_tx.wit.vtxinwit[0].scriptWitness.stack = [contract_sig, bob_withdraw_tapscript, bob_control_block]

        #caroll_withdraw_hashtype = SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_GROUP_ANYPUBKEY | SIGHASH_GROUP_ANYAMOUNT
        #caroll_withdraw_hash = TaprootSignatureHash(caroll_withdraw_tx, [setup_tx_output], caroll_withdraw_hashtype, 0, True, script=caroll_withdraw_tapscript, annex=None)
        #contract_sig = sign_schnorr(aggregated_contract_seckey, caroll_withdraw_hash) #TODO: flip r ? flip p ?
        #caroll_control_block = bytes([pool_tree[4]["s2"][1] + pool_tree[2]]) + pool_tree[1] + pool_tree[4]["s2"][2]
        #caroll_withdraw_tx.wit.vtxinwit.append(CTxInWitness())
        #caroll_withdraw_tx.wit.vtxinwit[0].scriptWitness.stack = [contract_sig, caroll_withdraw_tapscript, caroll_control_block]

        #dave_withdraw_hashtype = SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_GROUP_ANYPUBKEY | SIGHASH_GROUP_ANYAMOUNT
        #dave_withdraw_hash = TaprootSignatureHash(dave_withdraw_tx, [setup_tx_output], dave_withdraw_hashtype, 0, True, script=dave_withdraw_tapscript, annex=None)
        #contract_sig = sign_schnorr(aggregated_contract_seckey, dave_withdraw_hash) #TODO: flip r ? flip p ?
        #dave_control_block = bytes([pool_tree[4]["s3"][1] + pool_tree[2]]) + pool_tree[1] + pool_tree[4]["s3"][2]
        #dave_withdraw_tx.wit.vtxinwit.append(CTxInWitness())
        #dave_withdraw_tx.wit.vtxinwit[0].scriptWitness.stack = [contract_sig, caroll_withdraw_tapscript, dave_control_block]

        # We cancel Alice contribution from the aggregated key
        affine_Pa = SECP256K1.affine(Pa)
        Pna = SECP256K1.negate(Pa)
        affine_Pna = SECP256K1.affine(Pna)

        Pbcd = SECP256K1.add(pool_pubkey, Pna)
        updated_pool_key = SECP256K1.affine(Pbcd)
        updated_pool_tree = taproot_construct(updated_pool_key[0].to_bytes(32, 'big'), [("s1", bob_withdraw_tapscript), ("s2", caroll_withdraw_tapscript), ("s3", dave_withdraw_tapscript)])
        tweaked = tweak_add_pubkey(updated_pool_key[0].to_bytes(32, 'big'), updated_pool_tree[3])
        updated_merkle_root = taproot_tree_helper([("s1", bob_withdraw_tapscript), ("s2", caroll_withdraw_tapscript), ("s3", dave_withdraw_tapscript)])
        print("taproot root " + hex(int.from_bytes(updated_merkle_root[1], 'little')))
        print("U pubkey " + hex(int.from_bytes(updated_pool_key[0].to_bytes(32, 'big'), 'little')))
        print("Q pubkey " + hex(int.from_bytes(tweaked[0], 'little')))
        print("negated " + str(tweaked[1]))
        print("tweak " + hex(int.from_bytes(updated_pool_tree[3], 'little')))

        alice_withdraw_tx.vout.append(CTxOut(bob_amount + caroll_amount + dave_amount, updated_pool_tree[0]))
        # Sign the withdraw transaction with `SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_ANYPUBKEY | SIGHASH_ANYAMOUNT`
        # ANNEX_TAG + ANNEX_GROUP + length-field + group_count + ANNEX_ANYPUBKEY + length-field + anypubkey-tagged outputs + ANNEX_ANYAMOUNT + length-field + anyamount-tagged outputs TODO: a helper would be nice
        alice_annex = int(0x50).to_bytes(1, 'big') + int(0x00).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big')
        alice_withdraw_hashtype = SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_GROUP_ANYPUBKEY | SIGHASH_GROUP_ANYAMOUNT
        alice_withdraw_hash = TaprootSignatureHash(alice_withdraw_tx, [setup_tx_output], alice_withdraw_hashtype, 0, True, script=alice_withdraw_tapscript, annex=alice_annex, key_ver=1, group_outputs=[0, 1], group_anypubkey=[0, 1], group_anyamount=[0, 1])
        contract_sig = sign_schnorr(aggregated_contract_seckey, alice_withdraw_hash)
        alice_control_block = bytes([pool_tree[4]["s0"][1] + pool_tree[2]]) + pool_tree[1] + pool_tree[4]["s0"][2]
        alice_withdraw_tx.wit.vtxinwit.append(CTxInWitness())
        print("contract sig " + str(contract_sig[0]))
        alice_withdraw_tx.wit.vtxinwit[0].scriptWitness.stack = [contract_sig + int(alice_withdraw_hashtype).to_bytes(1, 'little'), alice_withdraw_tapscript, alice_control_block, alice_annex]

        alice_txid = node.sendrawtransaction(hexstring=alice_withdraw_tx.serialize().hex(), maxfeerate=0)

        #assert_raises_rpc_error(-26, 'non-mandatory-script-verify-flag (OP_SUCCESSx reserved for soft-fork upgrades)', node.sendrawtransaction, hexstring=alice_withdraw_tx.serialize().hex(), maxfeerate=0)
        assert alice_txid in node.getrawmempool()


if __name__ == '__main__':
    CoinpoolTest().main()
