// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ALTNET_CONTEXT_H
#define BITCOIN_ALTNET_CONTEXT_H

namespace interfaces {
class Validation;
} // namespace interfaces

struct AltnetContext {
    interfaces::Validation* validation{nullptr};

    AltnetContext();
    ~AltnetContext();
};

#endif // BITCOIN_ALTNET_CONTEXT_H
