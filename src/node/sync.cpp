// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/sync.h>

#include <chainparams.h>
#include <primitives/block.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>

void Sync::ThreadServiceRequests()
{
    auto& consensus_params = Params().GetConsensus();
    while (!m_interrupt) {
        // Loop for the earliest start position among requests.
        const CBlockIndex* min_start = nullptr;
        const CBlockIndex* ancestor = nullptr;
        for (auto& request : m_request_start) {
            // Find fork between chain tip and client
            // local view, if there is one, ask client to rollback
            // its state until common ancestor
            {
                LOCK(cs_main);
                ancestor = ChainActive().FindFork(request.second);
	    }
            if (ancestor && ancestor->nHeight != (request.second)->nHeight) {
                while (request.second && request.second->nHeight != ancestor->nHeight) {
			CBlock block;
			//XXX NODE_NETWORK_LIMITED
			ReadBlockFromDisk(block, request.second, consensus_params);
                        CBlockIndex *pprev = request.second->pprev;
			request.first->BlockDisconnected(block, request.second->nHeight, pprev->GetMedianTimePast());
			request.second = pprev;
		}
            }
	    if (!ancestor) {
		LOCK(cs_main);
		// If locator provided isn't among block index,
		// resync since genesis.
		request.second = ChainActive().Genesis();
	    }
            if (!min_start || min_start->nHeight > (request.second)->nHeight) {
                min_start = request.second;
            }
        }
        if (min_start) {
            // Read next block and send notifications.
            const CBlockIndex* next = nullptr;
            {
                LOCK(cs_main);
		if (min_start->nHeight > 0) {
                    assert(min_start->pprev);
                    next = ChainActive().Next(min_start->pprev);
                } else {
                    next = min_start;
                }
            }
            if (next) {
                CBlock block;
                ReadBlockFromDisk(block, next, consensus_params);
                for (auto& request : m_request_start) {
                    (request.first)->BlockConnected(block, {}, next->nHeight, next->GetMedianTimePast());
                    request.second = next;
                    // To avoid any race condition where callback would miss block connection,
                    // compare against tip and register validation interface in one sequence
                    LOCK(cs_main);
                    CBlockIndex* tip = ChainActive().Tip();
                    CBlockIndex* pindex = LookupBlockIndex(block.GetHash());
                    if (tip->GetBlockHash() == pindex->GetBlockHash()) {
			CBlockLocator locator = ::ChainActive().GetLocator(request.second);
                        (request.first)->HandleNotifications(locator, pindex->nHeight, pindex->GetMedianTimePast());
                        m_request_start.erase(request.first);
                    }
                }
            }
        }
    }
    // Let wallet commit locator if needed
    for (auto& request : m_request_start) {
        if (!request.second) continue;
        LOCK(cs_main);
        CBlockLocator locator = ::ChainActive().GetLocator(request.second);
        (request.first)->ChainStateFlushed(locator);
    }
}

void Sync::AddRequest(interfaces::Chain::Notifications& callback, const CBlockLocator& locator)
{
    LOCK(cs_main);
    // If fork is superior at MAX_LOCATOR_SZ, sync is going to be processed
    // from genesis. If reorg of this size happens, sync performance hit
    // isn't the main problem.
    m_request_start[&callback] = LookupBlockIndex(locator.vHave.front());
}

void Sync::StartServiceRequests()
{
    threadServiceRequests = std::thread(&TraceThread<std::function<void()>>, "rescan", std::bind(&Sync::ThreadServiceRequests, this));
}

void Sync::InterruptServiceRequests()
{
    m_interrupt();
}

void Sync::StopServiceRequests()
{
    if (threadServiceRequests.joinable()) {
        threadServiceRequests.join();
    }
}
