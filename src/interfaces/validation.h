// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_VALIDATION_H
#define BITCOIN_INTERFACES_VALIDATION_H

#include <uint256.h>

#include <vector>
#include <stdint.h>

namespace interfaces {

struct BlockHeader;

//! Inteface giving clients access to the validation engine.
class Validation
{
public:
    virtual ~Validation() {}

    // Check if headers are valid.
    virtual bool validateHeaders(const BlockHeader& header) = 0;
};

struct BlockHeader {
    int block_version;
    uint64_t block_time;
    uint256 block_hash;
};

} // namespace interfaces

#endif // BITCOIN_INTERFACES_VALIDATION_H
