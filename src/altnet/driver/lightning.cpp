// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <interfaces/init.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/translation.h>

#include <cstdio>

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

int main(int argc, char* argv[])
{
    int exit_status;

    SetupEnvironment();

    SelectBaseParams(CBaseChainParams::REGTEST);

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

    StartAltnetLightning(argc, argv, exit_status);
    if (exit_status) {
        LogPrintf("startSpawnProcess failure\n");
        return exit_status;
    }
    // This process is going to `Protocol->server()` until exit.
}
