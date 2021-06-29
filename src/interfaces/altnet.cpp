// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/context.h>
#include <interfaces/altnet.h>

#include <util/system.h>

namespace interfaces {
namespace {
class AltnetImpl : public Altnet
{
public:
    AltnetImpl(AltnetContext& altnet, Validation& validation) {
        LogPrintf("Inside altnet\n");
        validation.helloworld("MOAR");
        m_context = altnet;
        m_context.validation = &validation;
        m_context.validation->helloworld("LESS");
    }

    AltnetContext m_context;

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
        //TODO: why it doesn't bind ? who is killed first?

        // Call ProxyClient's "helloworld"
        m_context.validation->helloworld("HELLO");
    }
};
} // namespace
std::unique_ptr<Altnet> MakeAltnet(AltnetContext& altnet, Validation& validation) {
    return std::make_unique<AltnetImpl>(altnet, validation);
}
} // namespace interfaces
