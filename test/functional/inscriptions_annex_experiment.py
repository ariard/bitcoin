#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test inscriptions embedded in the annex"""

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
        COIN,
)

from test_framework.script import (
        CScript,
        OP_IF,
        OP_FALSE,
        OP_PUSHDATA1,
        OP_ENDIF,
        OP_1,
        OP_0,
        taproot_construct,
)

from test_framework.test_framework import BitcoinTestFramework

from test_framework.wallet import MiniWallet

def generate_commitment_tx(wallet, coin, pt2r_scriptpubkey):

    commitment_tx = CTransaction()

    commitment_tx.vin.append(CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']), b""))
    commitment_tx.vout.append(CTxOut(int(49.99998 * COIN), pt2r_scriptpubkey))
    commitment_tx.rehash()

    wallet.sign_tx(commitment_tx)
    return commitment_tx

def generate_enveloppe_script(data_payload):

    enveloppe_script = CScript([OP_IF,
        OP_PUSHDATA1, 4,  b'ord',
        OP_1,
        OP_PUSHDATA1, 25, b'text/plain;charset=utf-8',
        OP_0,
        OP_PUSHDATA1, 14, data_payload,
        OP_ENDIF,
    ])

    return enveloppe_script

class InscriptionsAnnexTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2

    def test_inscriptions_embedded_annex(self):
        node = self.nodes[0]

        self.generate(node, 501)

        self.sync_all()

        coin_1 = self.wallet.get_utxo()

        wallet = self.wallet

        # Legacy flow:
        # We generate an envelopped with inscription as data payload
        env_script = generate_enveloppe_script(b'Hello, world!')

        # We embed it in a taproot tree
        tapkey = generate_privkey()
        scripts = [("enveloppe", env_script)]
        pubs = [compute_xonly_pubkey(tapkey)[0]]
        tap = taproot_construct(pubs[0], scripts)

        # We broadcast the commitment_tx - commit the inscription
        commitment_tx = generate_commitment_tx(wallet, coin_1, tap.scriptPubKey)

        node.sendrawtransaction(hexstring=commitment_tx.serialize().hex(), maxfeerate=0)

        # We broadcast the reveal_tx - reveal the inscription

        # New flow:
        # We have an on-chain PT2R
        # We generate an inscription
        # We commit to the inscription in a bip341 signature ("sha_annex")
        # We commit to an array of inscripttions embedded in the annex by using key path
        # Once reveal transaction included, the annex is final, any alternative signed annex disregarded 

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_inscriptions_embedded_annex()

if __name__ == '__main__':
    InscriptionsAnnexTest().main()
