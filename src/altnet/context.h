// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ALTNET_CONTEXT_H
#define BITCOIN_ALTNET_CONTEXT_H

#include <interfaces/validation.h>

namespace interfaces {
class Init;
} // namespace interfaces

struct AltnetContext {
    AltnetContext();
    ~AltnetContext();
    interfaces::Validation* validation{nullptr};
    interfaces::Init* init{nullptr};
};

#endif // BITCOIN_ALTNET_CONTEXT_H
