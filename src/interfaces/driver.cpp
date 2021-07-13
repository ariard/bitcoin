// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/driver.h>
#include <interfaces/netwire.h>
#include <util/system.h>

namespace interfaces {
namespace {
class DriverImpl : public Driver
{
public:
    DriverImpl(std::unique_ptr<Netwire> netwire) {
        LogPrintf("inside a driver\n");

        BlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.hashMerkleRoot = uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        header.nTime = 1296688602;
        header.nNonce = 2;
        header.nBits = 0x207fffff;

        netwire->sendHeaders(header);
    }
};
} // namespace
std::unique_ptr<Driver> MakeDriver(std::unique_ptr<interfaces::Netwire> netwire) {
    return std::make_unique<DriverImpl>(std::move(netwire));
}
} // namespace interfaces
