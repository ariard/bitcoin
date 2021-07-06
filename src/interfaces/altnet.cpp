// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/context.h>
#include <interfaces/altnet.h>
#include <interfaces/validation.h>

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
        //BlockHeader header;
        //header.nVersion = 1;
        //header.hashPrevBlock.SetNull();
        //header.hashMerkleRoot.SetNull();
        //header.nTime = 1231006505;
        //header.nBits = 2083236893;
        //header.nNonce = 0x1d00ffff;
        if (!(m_context.validation)) {
            LogPrintf("Ooops, no validation interface\n");
        } else {
            LogPrintf("Sounds there is a validation interface...\n");
        }

        m_validation->helloworld("HELLO");
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
