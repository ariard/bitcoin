// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/altnet.h>

#include <util/memory.h>

namespace interfaces {
namespace {
class AltnetImpl : public Altnet
{
public:
    void start_transport() override {}
};
} // namespace
std::unique_ptr<Altnet> MakeAltnet() { return MakeUnique<AltnetImpl>(); }
} // namespace interfaces
