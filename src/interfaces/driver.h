// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_DRIVER_H
#define BITCOIN_INTERFACES_DRIVER_H

#include <memory>

namespace interfaces {

//! Interface giving orchester to direct drivers
class Driver
{
public:
    virtual ~Driver() {}

    virtual void stop() = 0;
};

std::unique_ptr<Driver> MakeDriver();

} // namespace interfaces

#endif // BITCOIN_INTERFACES_DRIVER_H
