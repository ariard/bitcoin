// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_VALIDATION_H
#define BITCOIN_INTERFACES_VALIDATION_H

#include <primitives/block.h>

#include <vector>

namespace interfaces {

//! Inteface giving clients access to the validation engine.
class Validation
{
public:
    virtual ~Validation() {}

    // Check if headers are valid.
    virtual bool validateHeaders(const CBlockHeader& header) = 0;
};

struct BlockHeader
{
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
}

} // namespace interfaces

#endif // BITCOIN_INTERFACES_VALIDATION_H
