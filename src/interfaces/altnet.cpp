// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/context.h>
#include <interfaces/altnet.h>
#include <interfaces/driver.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <interfaces/validation.h>

#include <uint256.h>
#include <util/system.h>

namespace interfaces {
namespace {
class AltnetImpl : public Altnet
{
public:
    AltnetImpl(AltnetContext& altnet, std::unique_ptr<Validation> validation) : m_validation(std::move(validation)) {
        LogPrintf("Inside altnet\n");
        m_context = altnet;
    }

    AltnetContext m_context;
    std::unique_ptr<Validation> m_validation;

    void sendgenesis() override {

        BlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.hashMerkleRoot = uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        header.nTime = 1296688602;
        header.nNonce = 2;
        header.nBits = 0x207fffff;

        //m_validation->helloworld("HELLO");
        if (m_validation->validateHeaders(header)) {
            LogPrintf("Valid genesis header!");
        } else {
            LogPrintf("Invalid genesis header!");
        }
    }

    void startdriver(const std::string& driver_name) override {
        LogPrintf("starting %s\n", driver_name);
        auto server = m_context.init->ipc()->spawnProcess(driver_name.data());
        auto driver = server->makeDriver();
        m_context.init->ipc()->addCleanup(*driver, [server = server.release()] { delete server; });
        driver.reset();
        server.reset();
    }

    void stop() override {
        LogPrintf("Shutdown of altnet...");
        exit(0);
    }
};
} // namespace
std::unique_ptr<Altnet> MakeAltnet(AltnetContext& altnet, std::unique_ptr<interfaces::Validation> validation) {
    return std::make_unique<AltnetImpl>(altnet, std::move(validation));
}
} // namespace interfaces
