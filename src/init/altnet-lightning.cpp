// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/driver/context.h>
#include <interfaces/driver.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <interfaces/netwire.h>
#include <util/translation.h>

#include <memory>

namespace init {
namespace {
const char* EXE_NAME = "altnet-lightning";

class AltnetLightningInit : public interfaces::Init
{
public:
    AltnetLightningInit(LightningContext& ln, const char* arg0)
        :   m_ln(ln),
            m_ipc(interfaces::MakeIpc(EXE_NAME, arg0, *this)) {}
    std::unique_ptr<interfaces::Driver> makeDriver(std::unique_ptr<interfaces::Netwire> netwire) override { return interfaces::MakeDriver(m_ln, std::move(netwire)); }
    interfaces::Ipc* ipc() override { return m_ipc.get(); }
    LightningContext& m_ln;
    std::unique_ptr<interfaces::Ipc> m_ipc;
};
} // namespace

} // namespace init

void StartAltnetLightning(LightningContext& ln, int argc, char *argv[], int& exit_status)
{
    auto init = std::make_unique<init::AltnetLightningInit>(ln, argc > 0 ? argv[0] : "");
    if (!init->m_ipc->startSpawnedProcess(argc, argv, exit_status)) {
        exit_status = 1;
    }
}
