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
    AltnetImpl(AltnetContext& altnet, interfaces::Validation& validation) {
        m_context = altnet;
        m_context.validation = &validation;
    }

    AltnetContext m_context;
};
} // namespace
std::unique_ptr<Altnet> MakeAltnet(AltnetContext& altnet, interfaces::Validation& validation) {
    return std::make_unique<AltnetImpl>(altnet, validation);
}
} // namespace interfaces
