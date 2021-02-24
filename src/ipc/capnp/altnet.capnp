# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0x888b4f7f51e691f8;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/altnet.h");
$Proxy.include("ipc/capnp/altnet.capnp.h");

interface Altnet $Proxy.wrap("interfaces::Altnet") {
    destroy @0 (context :Proxy.Context) -> ();
}
