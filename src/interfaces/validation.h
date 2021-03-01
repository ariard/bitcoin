// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_VALIDATION_H
#define BITCOIN_INTERFACES_VALIDATION_H

namespace interfaces {

//! Inteface giving clients access to the validation engine.
class Validation
{
public:
    virtual ~Validation() {}

    // Check if headers are valid.
    virtual bool ValidateHeaders(const std::vector<CBlockHeader>& headers) = 0;
};

} // namespace interfaces

#endif // BITCOIN_INTERFACES_VALIDATION_H
