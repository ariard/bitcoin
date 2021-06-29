# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0x888b4f7f51e69123;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/validation.h");
$Proxy.includeTypes("ipc/capnp/common-types.h");

interface Validation $Proxy.wrap("interfaces::Validation") {
    destroy @0 (context :Proxy.Context) -> ();
    validateHeaders @1 (context :Proxy.Context, header: BlockHeader) -> (result: Bool);
    helloworld @2 (context :Proxy.Context, message :Text) -> ();
}

struct BlockHeader $Proxy.wrap("interfaces::BlockHeader")
{
    nVersion @0 :Int32 $Proxy.name("nVersion");
    hashPrevBlock @1 :Data $Proxy.name("hashPrevBlock");
    hashMerkleRoot @2 :Data $Proxy.name("hashMerkleRoot");
    nTime @3 :UInt32 $Proxy.name("nTime");
    nBits @4 :UInt32 $Proxy.name("nBits");
    nNonce @5 :UInt32 $Proxy.name("nNonce");
}
