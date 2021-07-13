// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_NETWIRE_H
#define BITCOIN_INTERFACES_NETWIRE_H

#include <altnet/context.h>
#include <interfaces/validation.h>

#include <memory>

namespace interfaces {

class Netwire
{
public:
    virtual ~Netwire() {}

    // Check if headers are valid.
    virtual void sendHeaders(const interfaces::BlockHeader& header) = 0;
};

std::unique_ptr<Netwire> MakeNetwire(AltnetContext& altnet);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_NETWIRE_H
