// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <util/translation.h>

#include <memory>

namespace init {
namespace {
const char* EXE_NAME = "altnet-lightning";

class AltnetLightningInit : public interfaces::Init
{
public:
    AltnetLightningInit(const char* arg0)
        : m_ipc(interfaces::MakeIpc(EXE_NAME, arg0, *this)) {}
    interfaces::Ipc* ipc() override { return m_ipc.get(); }
    std::unique_ptr<interfaces::Ipc> m_ipc;
};
} // namespace

} // namespace init

void StartAltnetLightning(int argc, char *argv[], int& exit_status)
{
    auto init = std::make_unique<init::AltnetLightningInit>(argc > 0 ? argv[0] : "");
    if (!init->m_ipc->startSpawnedProcess(argc, argv, exit_status)) {
        exit_status = 1;
    }
}
