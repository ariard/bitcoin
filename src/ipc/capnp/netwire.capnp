# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0x888b4f7f51e69112;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/netwire.h");
$Proxy.include("interfaces/validation.h");
$Proxy.includeTypes("ipc/capnp/init-types.h");
$Proxy.includeTypes("ipc/capnp/common-types.h");

using Validation = import "validation.capnp";

interface Netwire $Proxy.wrap("interfaces::Netwire") {
    destroy @0 (context :Proxy.Context) -> ();
    sendHeaders @1 (context :Proxy.Context, header: Validation.BlockHeader) -> ();
}
