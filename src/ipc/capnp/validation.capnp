# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0x888b4f7f51e691f4;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/validation.h");
$Proxy.include("ipc/capnp/validation.capnp.h");

interface Validation $Proxy.wrap("interfaces::Validation") {
    destroy @0 (context :Proxy.Context) -> ();
    validateHeaders @1 (context :Proxy.Context, headers :BlockHeader) -> (result: Bool);
}

struct BlockHeader $Proxy.wrap("BlockHeader")
{
    nVersion @0 :Int32;
    hashPrevBlock @1 :Data;
    hashMerkleRoot @2 :Data;
    nTime @3 :UInt32;
    nBits @4 :UInt32;
    nNonce @5 :UInt32;
}
