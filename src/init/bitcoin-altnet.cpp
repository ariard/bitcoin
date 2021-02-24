// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/context.h>
#include <interfaces/altnet.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <node/ui_interface.h>
#include <util/memory.h>
#include <util/translation.h>

#include <memory>

namespace init {
namespace {
const char* EXE_NAME = "bitcoin-altnet";

class BitcoinAltnetInit : public interfaces::Init
{
public:
    BitcoinAltnetInit(AltnetContext& altnet, const char* arg0)
        : m_altnet(altnet),
          m_ipc(interfaces::MakeIpc(EXE_NAME, arg0, *this)) {}
    std::unique_ptr<interfaces::Altnet> makeAltnet(interfaces::Validation& validation) override { return MakeAltnet(m_altnet, validation); }
    interfaces::Ipc* ipc() override { return m_ipc.get(); }
    AltnetContext& m_altnet;
    std::unique_ptr<interfaces::Ipc> m_ipc;
};
} // namespace
} // namespace init

namespace interfaces {
void StartAltnet(AltnetContext& altnet, int argc, char* argv[], int& exit_status)
{
    auto init = MakeUnique<init::BitcoinAltnetInit>(altnet, argc > 0 ? argv[0] : "");
    if (!init->m_ipc->startSpawnedProcess(argc, argv, exit_status)) {
        InitError(Untranslated("bitcoin-altnet called incorrectly (not as a spawned process), exiting."));
        exit_status = 1;
    }
}
} // namespace interfaces
