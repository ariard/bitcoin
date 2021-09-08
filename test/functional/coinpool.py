#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test generation and spending of a Coinpool output"""

import struct

from test_framework.util import (
        assert_equal,
        assert_raises_rpc_error
)

from test_framework.test_framework import BitcoinTestFramework

from test_framework.key import (
        ECKey,
        EllipticCurve,
        compute_xonly_pubkey,
        generate_privkey,
        sign_schnorr,
        tweak_add_privkey,
        tweak_add_pubkey
)
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
        SIGHASH_ALL,
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
        self.setup_clean_chain = True
        self.extra_args = [['-minrelaytxfee=0']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.generate(101)
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
        if SECP256K1.has_even_y(Pa) == False:
            print("Pa odd")
        else:
            print("Pa even")

        xb = int.from_bytes(bob_pool_pubkey, 'big')
        Pb = SECP256K1.lift_x(xb)
        if SECP256K1.has_even_y(Pb) == False:
            print("Pb odd")
        else:
            print("Pb even")

        xc = int.from_bytes(caroll_pool_pubkey, 'big')
        Pc = SECP256K1.lift_x(xc)
        if SECP256K1.has_even_y(Pc) == False:
            print("Pc odd")
        else:
            print("Pc even")

        xd = int.from_bytes(dave_pool_pubkey, 'big')
        Pd = SECP256K1.lift_x(xd)
        print("before, Pd pubkey " + hex(int.from_bytes(Pd[0].to_bytes(32, 'big'), 'little')))
        if SECP256K1.has_even_y(Pd) == False:
            print("Pd odd")
        else:
            print("Pd even")

        Pab = SECP256K1.add(Pa, Pb)
        Pabc = SECP256K1.add(Pab, Pc)

        #XXX: control substract sequence
        Pabcd = SECP256K1.add(Pabc, Pd)

        Pna = SECP256K1.negate(Pa)
        Pbcd = SECP256K1.add(Pabcd, Pna)

        Pnb = SECP256K1.negate(Pb)
        Pcd = SECP256K1.add(Pbcd, Pnb)

        Pnc = SECP256K1.negate(Pc)
        Pd2 = SECP256K1.add(Pcd, Pnc)

        assert(SECP256K1.affine(Pd) == SECP256K1.affine(Pd2))

        pool_pubkey = SECP256K1.affine(Pabcd)
        if SECP256K1.has_even_y(pool_pubkey):
            internal_evenness = bytes(0x01)
        else:
            internal_evenness = bytes(0x02)

        if SECP256K1.has_even_y(pool_pubkey) == False:
            print("Pabcd odd")
            #pool_pubkey = SECP256K1.negate(pool_pubkey)
        else:
            print("Pabcd even")

        # Generate the participants amounts
        alice_amount = int(COIN / 10)

        bob_amount = int(COIN / 10 * 2)

        caroll_amount = int(COIN / 10 * 3)

        dave_amount = int(COIN / 10 * 4)

        # Aggregated pubkey
        aggregated_contract_seckey = generate_privkey()
        aggregated_contract_pubkey = compute_xonly_pubkey(aggregated_contract_seckey)[0]

        # Generate the withdraw scripts
        alice_withdraw_tapscript = CScript([OP_1, alice_pool_pubkey, OP_MERKLESUB, OP_DROP, OP_DROP, int(1).to_bytes(1, 'big') + aggregated_contract_pubkey, OP_CHECKSIG])

        bob_withdraw_tapscript = CScript([OP_1, bob_pool_pubkey, OP_MERKLESUB, OP_DROP, OP_DROP, int(1).to_bytes(1, 'big') +  aggregated_contract_pubkey, OP_CHECKSIG])

        caroll_withdraw_tapscript = CScript([OP_1, caroll_pool_pubkey, OP_MERKLESUB, OP_DROP, OP_DROP, int(1).to_bytes(1, 'big') + aggregated_contract_pubkey, OP_CHECKSIG])

        dave_withdraw_tapscript = CScript([OP_1, dave_pool_pubkey, OP_MERKLESUB, OP_DROP, OP_DROP, int(1).to_bytes(1, 'big') + aggregated_contract_pubkey, OP_CHECKSIG])

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
        bob_withdraw_tx.vout.append(CTxOut(bob_amount, bob_exit_scriptpubkey))

        caroll_withdraw_tx = CTransaction()
        caroll_withdraw_tx.vout.append(CTxOut(caroll_amount, caroll_exit_scriptpubkey))

        # We cancel Alice contribution from the aggregated key
        #if SECP256K1.has_even_y(Pa) == False:
        #    print("Pa odd")
        #else:
        #    print("Pa even")
        Pna = SECP256K1.negate(Pa)

        P = SECP256K1.add(pool_pubkey, Pna)
        if SECP256K1.has_even_y(P) == False:
            print("P is odd")
            P = SECP256K1.negate(P)
        else:
            print("P is even")
        bcd_internal_key = SECP256K1.affine(Pbcd)

        #XXX: checkpoint 1 assert
        assert(SECP256K1.affine(Pbcd) == SECP256K1.affine(P))

        return;
        print("P pubkey " + hex(int.from_bytes(pool_pubkey[0].to_bytes(32, 'big'), 'little')))
        print("S pubkey " + hex(int.from_bytes(Pna[0].to_bytes(32, 'big'), 'little')))
        print("U pubkey " + hex(int.from_bytes(bcd_internal_key[0].to_bytes(32, 'big'), 'little')))

        #print("after removal, Pbcd pubkey " + hex(int.from_bytes(updated_pool_key[0].to_bytes(32, 'big'), 'little')))
        #if SECP256K1.has_even_y(updated_pool_key) == False:
        #    print("Pbcd odd")
        #    updated_pool_key = SECP256K1.negate(bcd_internal_key)
        #else:
        #    print("Pbcd even")
        #print("after removal, negated Pbcd pubkey " + hex(int.from_bytes(updated_pool_key[0].to_bytes(32, 'big'), 'little')))

        alice_pool_tree = taproot_construct(bcd_internal_key[0].to_bytes(32, 'big'), [("s1", bob_withdraw_tapscript), ("s2", caroll_withdraw_tapscript), ("s3", dave_withdraw_tapscript)])
        tweaked = tweak_add_pubkey(bcd_internal_key[0].to_bytes(32, 'big'), alice_pool_tree[3])
        updated_merkle_root = taproot_tree_helper([("s1", bob_withdraw_tapscript), ("s2", caroll_withdraw_tapscript), ("s3", dave_withdraw_tapscript)])
        #print("taproot root " + hex(int.from_bytes(updated_merkle_root[1], 'little')))
        #print("U pubkey " + hex(int.from_bytes(bcd_internal_key[0].to_bytes(32, 'big'), 'little')))
        #print("Q pubkey " + hex(int.from_bytes(tweaked[0], 'little')))
        #print("negated " + str(tweaked[1]))
        #print("tweak " + hex(int.from_bytes(alice_pool_tree[3], 'little')))

        alice_contract_output = CTxOut(bob_amount + caroll_amount + dave_amount, alice_pool_tree[0])
        alice_withdraw_tx.vout.append(alice_contract_output)
        # Sign the withdraw transaction with `SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_ANYPUBKEY | SIGHASH_ANYAMOUNT`
        # ANNEX_TAG + ANNEX_GROUP + length-field + group_count + ANNEX_ANYPUBKEY + length-field + anypubkey-tagged outputs + ANNEX_ANYAMOUNT + length-field + anyamount-tagged outputs TODO: a helper would be nice
        alice_annex = int(0x50).to_bytes(1, 'big') + int(0x00).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big')
        alice_withdraw_hashtype = SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_GROUP_ANYPUBKEY | SIGHASH_GROUP_ANYAMOUNT
        alice_withdraw_hash = TaprootSignatureHash(alice_withdraw_tx, [setup_tx_output], alice_withdraw_hashtype, 0, True, script=alice_withdraw_tapscript, annex=alice_annex, key_ver=1, group_outputs=[0, 1], group_anypubkey=[0, 1], group_anyamount=[0, 1])
        contract_sig = sign_schnorr(aggregated_contract_seckey, alice_withdraw_hash)
        alice_control_block = bytes([pool_tree[4]["s0"][1] + pool_tree[2]]) + pool_tree[1] + pool_tree[4]["s0"][2]
        alice_withdraw_tx.wit.vtxinwit.append(CTxInWitness())
        #print("contract sig " + str(contract_sig[0]))
        alice_withdraw_tx.wit.vtxinwit[0].scriptWitness.stack = [contract_sig + int(alice_withdraw_hashtype).to_bytes(1, 'little'), alice_withdraw_tapscript, alice_control_block, alice_annex]

        alice_txid = node.sendrawtransaction(hexstring=alice_withdraw_tx.serialize().hex(), maxfeerate=0)
        assert alice_txid in node.getrawmempool()

        ## We cancel Bob contribution from the aggregated key
        #if SECP256K1.has_even_y(Pb) == False:
        #    print("Pb odd")
        #else:
        #    print("Pb even")
        #Pnb = SECP256K1.negate(Pb)
        #Pcd = SECP256K1.add(bcd_internal_key, Pnb)
        #updated_pool_key = SECP256K1.affine(Pcd)
        #print("after removal, Pcd pubkey " + hex(int.from_bytes(updated_pool_key[0].to_bytes(32, 'big'), 'little')))
        #if SECP256K1.has_even_y(updated_pool_key) == False:
        #    print("Pcd odd")
        #    updated_pool_key = SECP256K1.negate(updated_pool_key)
        #else:
        #    print("Pcd even")
        #print("after removal, negated Pcd pubkey " + hex(int.from_bytes(updated_pool_key[0].to_bytes(32, 'big'), 'little')))

        #bob_pool_tree = taproot_construct(updated_pool_key[0].to_bytes(32, 'big'), [("s2", caroll_withdraw_tapscript), ("s3", dave_withdraw_tapscript)])
        #tweaked = tweak_add_pubkey(updated_pool_key[0].to_bytes(32, 'big'), bob_pool_tree[3])
        #updated_merkle_root = taproot_tree_helper([("s2", caroll_withdraw_tapscript), ("s3", dave_withdraw_tapscript)])

        #bob_withdraw_tx.vin.append(CTxIn(COutPoint(int(alice_txid, 16), 1), b"", 0xffffffff))
        #bob_contract_output = CTxOut(caroll_amount + dave_amount, bob_pool_tree[0])
        #bob_withdraw_tx.vout.append(bob_contract_output)
        ## ANNEX_TAG + ANNEX_GROUP + length-field + group_count + ANNEX_ANYPUBKEY + length-field + anypubkey-tagged outputs + ANNEX_ANYAMOUNT + length-field + anyamount-tagged outputs TODO: a helper would be nice
        #bob_annex = int(0x50).to_bytes(1, 'big') + int(0x00).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big')
        #bob_withdraw_hashtype = SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_GROUP_ANYPUBKEY | SIGHASH_GROUP_ANYAMOUNT
        #bob_withdraw_hash = TaprootSignatureHash(bob_withdraw_tx, [alice_contract_output], bob_withdraw_hashtype, 0, True, script=bob_withdraw_tapscript, annex=bob_annex, key_ver=1, group_outputs=[0, 1], group_anypubkey=[0, 1], group_anyamount=[0, 1])
        #contract_sig = sign_schnorr(aggregated_contract_seckey, bob_withdraw_hash)
        #bob_control_block = bytes([alice_pool_tree[4]["s1"][1] + alice_pool_tree[2]]) + alice_pool_tree[1] + alice_pool_tree[4]["s1"][2]
        #bob_withdraw_tx.wit.vtxinwit.append(CTxInWitness())
        #bob_withdraw_tx.wit.vtxinwit[0].scriptWitness.stack = [contract_sig + int(bob_withdraw_hashtype).to_bytes(1, 'little'), bob_withdraw_tapscript, bob_control_block, bob_annex]

        #bob_txid = node.sendrawtransaction(hexstring=bob_withdraw_tx.serialize().hex(), maxfeerate=0)
        #assert bob_txid in node.getrawmempool()

        ## We cancel Caroll contribution from the aggregated key
        #if SECP256K1.has_even_y(Pc) == False:
        #    print("Pc odd")
        #else:
        #    print("Pc even")
        #Pnc = SECP256K1.negate(Pc)
        #Pd = SECP256K1.add(updated_pool_key, Pnc)
        #updated_pool_key = SECP256K1.affine(Pd)
        #print("after removal, Pd pubkey " + hex(int.from_bytes(updated_pool_key[0].to_bytes(32, 'big'), 'little')))
        #if SECP256K1.has_even_y(updated_pool_key) == False:
        #    print("Pd odd")
        #    updated_pool_key = SECP256K1.negate(updated_pool_key)
        #else:
        #    print("Pd odd")
        #print("after removal, negated Pd pubkey " + hex(int.from_bytes(updated_pool_key[0].to_bytes(32, 'big'), 'little')))

        #caroll_pool_tree = taproot_construct(updated_pool_key[0].to_bytes(32, 'big'), [("s3", dave_withdraw_tapscript)])
        #tweaked = tweak_add_pubkey(updated_pool_key[0].to_bytes(32, 'big'), caroll_pool_tree[3])
        #print("Q pubkey " + hex(int.from_bytes(tweaked[0], 'little')))
        #updated_merkle_root = taproot_tree_helper([("s3", dave_withdraw_tapscript)])

        #caroll_withdraw_tx.vin.append(CTxIn(COutPoint(int(bob_txid, 16), 1), b"", 0xffffffff))
        #caroll_contract_output = CTxOut(dave_amount, caroll_pool_tree[0])
        #caroll_withdraw_tx.vout.append(caroll_contract_output)
        ## ANNEX_TAG + ANNEX_GROUP + length-field + group_count + ANNEX_ANYPUBKEY + length-field + anypubkey-tagged outputs + ANNEX_ANYAMOUNT + length-field + anyamount-tagged outputs TODO: a helper would be nice
        #caroll_annex = int(0x50).to_bytes(1, 'big') + int(0x00).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big') + int(0x01).to_bytes(1, 'big') + int(0x02).to_bytes(1, 'big')
        #caroll_withdraw_hashtype = SIGHASH_ANYPREVOUT | SIGHASH_GROUP | SIGHASH_GROUP_ANYPUBKEY | SIGHASH_GROUP_ANYAMOUNT
        #caroll_withdraw_hash = TaprootSignatureHash(caroll_withdraw_tx, [bob_contract_output], caroll_withdraw_hashtype, 0, True, script=caroll_withdraw_tapscript, annex=caroll_annex, key_ver=1, group_outputs=[0, 1], group_anypubkey=[0, 1], group_anyamount=[0, 1])
        #contract_sig = sign_schnorr(aggregated_contract_seckey, caroll_withdraw_hash)
        #caroll_control_block = bytes([bob_pool_tree[4]["s2"][1] + bob_pool_tree[2]]) + bob_pool_tree[1] + bob_pool_tree[4]["s2"][2]
        #caroll_withdraw_tx.wit.vtxinwit.append(CTxInWitness())
        #caroll_withdraw_tx.wit.vtxinwit[0].scriptWitness.stack = [contract_sig + int(caroll_withdraw_hashtype).to_bytes(1, 'little'), caroll_withdraw_tapscript, caroll_control_block, caroll_annex]

        #caroll_txid = node.sendrawtransaction(hexstring=caroll_withdraw_tx.serialize().hex(), maxfeerate=0)
        #assert caroll_txid in node.getrawmempool()

        ## Dave realize a key-path spend
        #dave_exit_tx = CTransaction()
        #dave_exit_tx.vin.append(CTxIn(COutPoint(int(caroll_txid, 16), 1), b"", 0xffffffff))
        #dave_exit_tx.vout.append(CTxOut(dave_amount, dave_exit_scriptpubkey))
        #dave_exit_hashtype = SIGHASH_ALL
        #dave_exit_hash = TaprootSignatureHash(dave_exit_tx, [caroll_contract_output], dave_exit_hashtype, 0, True)

        #dave_pubkey = compute_xonly_pubkey(dave_pool_seckey)
        #tweaked_dave_seckey = tweak_add_privkey(dave_pool_seckey, caroll_pool_tree[3])
        #tweaked_pubkey = compute_xonly_pubkey(tweaked_dave_seckey)
        #xd = int.from_bytes(dave_pool_pubkey, 'big')
        #Pd = SECP256K1.lift_x(xd)
        #affine_Pd = SECP256K1.affine(Pd)
        #print("Pd pubkey " + hex(int.from_bytes(affine_Pd[0].to_bytes(32, 'big'), 'little')))

        ##print("dave pubkey " + hex(int.from_bytes(dave_pubkey[0], 'little')))
        #print("tweaked pubkey " + hex(int.from_bytes(tweaked_pubkey[0], 'little')))
        #print("")
        #keypath_sig = sign_schnorr(dave_pool_seckey, dave_exit_hash)
        #dave_exit_tx.wit.vtxinwit.append(CTxInWitness())
        #dave_exit_tx.wit.vtxinwit[0].scriptWitness.stack = [keypath_sig]

        #dave_txid = node.sendrawtransaction(hexstring=dave_exit_tx.serialize().hex(), maxfeerate=0)
        #assert dave_txid in node.getrawmempool()

if __name__ == '__main__':
    #TODO: implement even-only operations
    #TODO: anyprevout -> anyscript
    #TODO: pass control block
    #TODO: generate_players() + withdraw()
    CoinpoolTest().main()

#        Pnd = SECP256K1.negate(Pd)
#        Q = SECP256K1.add(Pabcd, Pnd)
#
#        #assert(SECP256K1.affine(Pabc) == SECP256K1.affine(Q))
#
#        Pnc = SECP256K1.negate(Pc)
#        Q = SECP256K1.add(Pabc, Pnc)
#
#        #assert(SECP256K1.affine(Pab) == SECP256K1.affine(Q))
#
#        Pna = SECP256K1.negate(Pa)
#        P = SECP256K1.add(Pabcd, Pna)
#
#        Pbc = SECP256K1.add(Pb, Pc)
#        Q = SECP256K1.add(Pbc, Pd)
#
#        #TODO: leverage P against A withdraw
#        #assert(SECP256K1.affine(P) == SECP256K1.affine(Q))
