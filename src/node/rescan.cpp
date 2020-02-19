// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/rescan.h>

#include <chainparams.h>
#include <primitives/block.h>
#include <util/system.h>

void Rescan::ThreadRescanRequest()
{
	while(!m_interrupt) {
		if (m_request_rescan.empty()) {
                    if (!m_interrupt.sleep_for(std::chrono::milliseconds(500))) return;
		}
		auto& rescan = m_request_rescan.back();
		m_request_rescan.back();
		do {
			CBlock block;
			if (!ReadBlockFromDisk(block, rescan.second, consensus_params)) break;
			rescan.first->RescanBlock(block, rescan.second);
			rescan.second++;
			//XXX: lock
		} while (!(rescan.third && rescan.second == *rescan.third) && rescan.third != ChainActive().Tip())
	}
}

void Rescan::AddRescan(interfaces::Chain::Notifications& callback, int64_t time, int* start_height, int* stop_height)
{
    if (!start_height) {
	    CBlockIndex* block = ::ChainActive().FindEarliestAtLeast(time, 0);
	    height = block->nHeight;
    } else {
	    height = *start_height;
    }
    m_request_rescan.insert(0, std::make_tuple(callback, height, stop_height));
}

void Rescan::StartRescanRequests()
{
    threadRescanRequests = std::thread(&TraceThread<std::function<void()>>, "rescan", std::bind(&Sync::ThreadRescanRequests, this));
}

void Rescan::InterruptServiceRequests()
{
    m_interrupt();
}

void Rescan::StopServiceRequests()
{
    if (threadRescanRequests.joinable()) {
        threadRescanRequests.join();
    }
}
