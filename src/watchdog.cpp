// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <watchdog.h>

#include <util/time.h>

CWatchdog::CWatchdog()
{
    nLastHeader = 0;
}

CWatchdog::~CWatchdog() {}

void CWatchdog::ScanAnomalies()
{
    // if nLastBlockTime+2 !=
    // blockk interval + variance
    // TODO: generate zmq event
}

void CWatchdog::LogHeader(const std::vector<CBlockHeader>& block)
{
    nLastHeader = GetTime();
}
