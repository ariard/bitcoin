// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DRIVER_CONTEXT_H
#define BITCOIN_DRIVER_CONTEXT_H

#include <memory>

namespace interfaces {
class Netwire;
} // namespace interfaces

struct LightningContext {
    std::unique_ptr<interfaces::Netwire> netwire;

    LightningContext();
    ~LightningContext();
};

#endif // BITCOIN_DRIVER_CONTEXT_H
