#!/usr/bin/env python3
# Copyright (c) 2024 The random folks on the Internet.
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BitVm implementation from my understanding of the paper"""

from test_framework.key import (
        ECKey,
        generate_privkey,
        compute_xonly_pubkey,
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
    OP_0,
    OP_1,
    OP_2,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKMULTISIG,
    OP_IF,
    OP_ELSE,
    OP_ENDIF,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_ENDIF,
    OP_TOALTSTACK,
    OP_FROMALTSTACK,
    OP_BOOLAND,
    OP_NOT,
    OP_DROP,
    OP_TRUE,
    hash160,
    SegwitV0SignatureHash,
    SIGHASH_ALL,
    taproot_construct
)

from test_framework.test_framework import BitcoinTestFramework

from test_framework.wallet import MiniWallet

def get_exit_script(locktime, verifier_key):
    return CScript([locktime, OP_CHECKSEQUENCEVERIFY, OP_DROP])

def get_funding_redeemscript(funder_pubkey, fundee_pubkey):
    return CScript([OP_2, funder_pubkey.get_bytes(), fundee_pubkey.get_bytes(), OP_2, OP_CHECKMULTISIG])

def generate_funding_tx(wallet, coin, funder_pubkey, fundee_pubkey):
    witness_script = get_funding_redeemscript(funder_pubkey, fundee_pubkey)
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    funding_tx_fee = 150 * 5

    funding_tx = CTransaction()
    funding_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
    funding_tx.vout.append(CTxOut(int(49.99998 * COIN), script_pubkey))
    funding_tx.rehash()

    wallet.sign_tx(funding_tx)
    return funding_tx

def generate_challenge_tx(funding_txid, funding_vout, paul_seckey, vicky_seckey, taproot_tree, input_amount):

    input_script = get_funding_redeemscript(paul_seckey.get_pubkey(), vicky_seckey.get_pubkey())

    challenge_tx_fee = 200 * 5
 
    challenge_tx = CTransaction()
    challenge_tx.vin.append(CTxIn(COutPoint(int(funding_txid, 16), 0), b""))
    challenge_tx.vout.append(CTxOut(int(input_amount - challenge_tx_fee), taproot_tree))

    sig_hash = SegwitV0SignatureHash(input_script, challenge_tx, 0, SIGHASH_ALL, int(input_amount))
    paul_sig = paul_seckey.sign_ecdsa(sig_hash) + b'\x01'
    vicky_sig = vicky_seckey.sign_ecdsa(sig_hash) + b'\x01'

    challenge_tx.wit.vtxinwit.append(CTxInWitness())
    challenge_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', paul_sig, vicky_sig, input_script]
    challenge_tx.rehash()

    return challenge_tx

def generate_response_tx(challenge_txid, challenge_vout, input_amount, preimage_1, preimage_2, logic_gate_script):

    witness_script = CScript([OP_TRUE])
    witness_program = sha256(witness_script)
    script_pubkey = CScript([OP_0, witness_program])

    response_tx_fee = 200 * 500

    response_tx = CTransaction()
    response_tx.vin.append(CTxIn(COutPoint(int(challenge_txid, 16), challenge_vout), b""))
    response_tx.vout.append(CTxOut(int(input_amount - response_tx_fee)), script_pubkey)

    # finish to generate witness

    return response_tx

def generate_binary_circuit_tree(scripts, ab_seckey):

    pubs = [compute_xonly_pubkey(ab_seckey)[0]]
    tap = taproot_construct(pubs[0], scripts)

    return tap.scriptPubKey

def generate_commitment_equivocation_script(list_preimages, vicky_seckey):

    left_even_hashlock = hash160(list_preimages[0])
    left_odd_hashlock = hash160(list_preimages[1])

    logic_gate_equivocation_script = CScript([OP_HASH160, left_even_hashlock,
        OP_HASH160, left_odd_hashlock, vicky_seckey.get_pubkey().get_bytes(), OP_CHECKSIG])

    return logic_gate_equivocation_script

def generate_logic_gate_commitment_script(list_preimages):

    left_even_hashlock = hash160(list_preimages[0])
    left_odd_hashlock = hash160(list_preimages[1])

    right_even_hashlock = hash160(list_preimages[2])
    right_odd_hashlock = hash160(list_preimages[3])

    output_even_hashlock = hash160(list_preimages[4])
    output_odd_hashlock = hash160(list_preimages[5])

    # Bit Commitment is the following excerpt of the script:
    #   OP_IF
    #       OP_HASH160
    #       <0xf5b44115a53f716b6f488de1098ee7c251418623>
    #       OP_EQUALVERIFY
    #       <1>
    #   OP_ELSE
    #       OP_HASH160
    #       <0xa74547c1ef0aa147c7428ab7e71664549be2a412>
    #       OP_EQUALVERIFY
    #       <0>
    #   OP_ENDIF

    logic_gate_commitment_script = CScript([OP_IF, OP_HASH160, left_even_hashlock, OP_EQUALVERIFY, OP_0,
        OP_ELSE, OP_HASH160, left_odd_hashlock, OP_EQUALVERIFY, OP_1,
        OP_ENDIF, OP_TOALTSTACK,
        OP_IF, OP_HASH160, right_even_hashlock, OP_EQUALVERIFY, OP_0,
        OP_ELSE, OP_HASH160, right_odd_hashlock, OP_EQUALVERIFY, OP_1,
        OP_ENDIF, OP_TOALTSTACK,
        OP_IF, OP_HASH160, output_even_hashlock, OP_EQUALVERIFY, OP_0,
        OP_ELSE, OP_HASH160, output_even_hashlock, OP_EQUALVERIFY, OP_1,
        OP_ENDIF, OP_FROMALTSTACK, OP_BOOLAND, OP_NOT, OP_FROMALTSTACK,
        OP_EQUALVERIFY
    ])

    return logic_gate_commitment_script

class BitVmTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2

    def test_bitvm_experiment(self):
        paul = self.nodes[0]
        paul_seckey = ECKey()
        paul_seckey.generate(True)

        vicky_seckey = ECKey()
        vicky_seckey.generate(True)

        self.generate(paul, 501)

        coin_1 = self.wallet.get_utxo()

        wallet = self.wallet

        preimage1 = hash160(b'the bit value')
        preimage2 = hash160(b'commitment is the')
        preimage3 = hash160(b'most elementary component')
        preimage4 = hash160(b'of the system')
        preimage5 = hash160(b'It allows the prover')
        preimage6 = hash160(b'to set the value of')

        list_preimages = [preimage1, preimage2, preimage3, preimage4, preimage5, preimage6]

        logic_gate_script_one = generate_logic_gate_commitment_script(list_preimages)
        exit_script = get_exit_script(2016, vicky_seckey)
        equivocation_script = generate_commitment_equivocation_script(list_preimages, vicky_seckey)

        # musig2 key or nothing-up-my-sleeve point.
        pv_tapkey = generate_privkey()
        scripts = [("gate_1", logic_gate_script_one), ("exit", exit_script), ("equivocation", equivocation_script)]
        taproot_tree = generate_binary_circuit_tree(scripts, pv_tapkey)

        funding_tx = generate_funding_tx(wallet, coin_1, paul_seckey.get_pubkey(), vicky_seckey.get_pubkey())

        # Transaction owned by Vicky the verifier
        challenge_tx = generate_challenge_tx(funding_tx.hash, 0, paul_seckey, vicky_seckey, taproot_tree, funding_tx.vout[0].nValue)

        paul.sendrawtransaction(hexstring=funding_tx.serialize().hex(), maxfeerate=0)

        assert paul.testmempoolaccept([challenge_tx.serialize().hex()])[0]["allowed"]

        # Now 3 steps can happen:
        #       - "exit": generate_exit_tx()
        #       - "equivocation": generate_equivocation_tx
        #       - "response": generate_response_tx 


    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_bitvm_experiment()

if __name__ == '__main__':
    BitVmTest().main()
