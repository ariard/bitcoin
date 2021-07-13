// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/driver/context.h>
#include <chainparamsbase.h>
#include <interfaces/init.h>
#include <interfaces/netwire.h>
#include <interfaces/validation.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/translation.h>

#include <chrono>
#include <functional>
#include <cstdio>
#include <memory>
#include <thread>

using interfaces::BlockHeader;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

void ThreadLightningHandler(LightningContext& ln) {

    BlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    header.nTime = 1296688602;
    header.nNonce = 2;
    header.nBits = 0x207fffff;

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (ln.netwire) {
            ln.netwire->sendHeaders(header);
        }
    }
}

int main(int argc, char* argv[])
{
    int exit_status;

    SetupEnvironment();

    SelectBaseParams(CBaseChainParams::MAIN);

    LogInstance().m_print_to_file = true;
    LogInstance().m_file_path = "debug-altnet-lightning.log";
    LogInstance().m_print_to_console = false;
    LogInstance().m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
    LogInstance().m_log_time_micros = DEFAULT_LOGTIMEMICROS;
    LogInstance().m_log_threadnames = DEFAULT_LOGTHREADNAMES;

    if (!LogInstance().StartLogging()) {
        throw std::runtime_error(strprintf("Could not open debug log file %s", LogInstance().m_file_path.string()));
    }

    LogPrintf("`altnet-lightning` process started!\n");

    LightningContext ln;
    auto threadLightningHandler = std::thread(&TraceThread<std::function<void()> >, "ln", std::function<void()>(std::bind(&ThreadLightningHandler, std::ref(ln))));

    StartAltnetLightning(ln, argc, argv, exit_status);
    if (exit_status) {
        LogPrintf("startSpawnProcess failure\n");
        return exit_status;
    }
    // This process is going to `Protocol->server()` until exit.
}
