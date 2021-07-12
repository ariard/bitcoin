// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ALTNET_CONTEXT_H
#define BITCOIN_ALTNET_CONTEXT_H

#include <memory>
#include <vector>

namespace interfaces {
class Driver;
class Init;
class Validation;
} // namespace interfaces

struct AltnetContext {
    interfaces::Init* init{nullptr};
    std::vector<std::unique_ptr<interfaces::Driver>> driver_clients;
    std::unique_ptr<interfaces::Validation> validation;

    AltnetContext();
    ~AltnetContext();
};

#endif // BITCOIN_ALTNET_CONTEXT_H
