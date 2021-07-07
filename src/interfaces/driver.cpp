// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/driver.h>
#include <util/system.h>

namespace interfaces {
namespace {
class DriverImpl : public Driver
{
public:
    DriverImpl() {
        LogPrintf("inside a driver\n");
    }

    void stop() override {
        LogPrintf("Shutdown of driver...");
        exit(0);
    }
};
} // namespace
std::unique_ptr<Driver> MakeDriver() {
    return std::make_unique<DriverImpl>();
}
} // namespace interfaces
