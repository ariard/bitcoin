// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/context.h>
#include <chainparamsbase.h>
#include <interfaces/init.h>
#include <interfaces/validation.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <uint256.h>

#include <cstdio>

using interfaces::BlockHeader;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

int main(int argc, char* argv[])
{
    int exit_status;

    SetupEnvironment();

    SelectBaseParams(CBaseChainParams::MAIN);

    LogInstance().m_print_to_file = true;
    LogInstance().m_file_path = "debug-altnet.log";
    LogInstance().m_print_to_console = false;
    LogInstance().m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
    LogInstance().m_log_time_micros = DEFAULT_LOGTIMEMICROS;
    LogInstance().m_log_threadnames = DEFAULT_LOGTHREADNAMES;

    if (!LogInstance().StartLogging()) {
        throw std::runtime_error(strprintf("Could not open debug log file %s", LogInstance().m_file_path.string()));
    }

    AltnetContext altnet;
    StartAltnet(altnet, argc, argv, exit_status);
    if (exit_status) {
        LogPrintf("startSpawnedProcess failure\n");
        return exit_status;
    }
    BlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetNull();
    header.nTime = 1231006505;
    header.nBits = 2083236893;
    header.nNonce = 0x1d00ffff;
    altnet.validation->validateHeaders(header);

    LogPrintf("This is Altnet!");
    while (true) {}
}
