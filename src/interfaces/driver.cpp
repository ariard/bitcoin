// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/driver/context.h>
#include <interfaces/driver.h>
#include <interfaces/netwire.h>
#include <util/system.h>

namespace interfaces {
namespace {
class DriverImpl : public Driver
{
public:
    DriverImpl(LightningContext& ln, std::unique_ptr<Netwire> netwire): m_ln(ln) {
        LogPrintf("inside a driver\n");

        m_ln.netwire = std::move(netwire);
    }

    LightningContext& m_ln;
};
} // namespace
std::unique_ptr<Driver> MakeDriver(LightningContext& context, std::unique_ptr<interfaces::Netwire> netwire) {
    return std::make_unique<DriverImpl>(context, std::move(netwire));
}
} // namespace interfaces
