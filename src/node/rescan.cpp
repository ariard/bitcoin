// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/rescan.h>

#include <chainparams.h>
#include <primitives/block.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>

void Rescan::ThreadServiceRequests()
{
    auto& consensus_params = Params().GetConsensus();
    while (!m_interrupt) {
        // Loop for the earliest start position among requests.
        const CBlockIndex* min_start = nullptr;
        const CBlockIndex* ancestor = nullptr;
        for (auto& request : m_request_start) {
            // If locator has not been found, request is handled
            // since genesis.
            if (!request.second) {
                LOCK(cs_main);
                request.second = ChainActive().Genesis();
                if (!request.second) continue;
            }
            // Find fork between chain tip and client
            // local view, if there is one, ask client to rewind
            // its state until common ancestor
            {
                LOCK(cs_main);
                ancestor = ChainActive().FindFork(request.second);
            }
            if (ancestor && ancestor->nHeight != (request.second)->nHeight) {
                (request.first)->Rewind((request.second)->nHeight, ancestor->nHeight);
                request.second = ancestor;
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
                    (request.first)->BlockConnected(block, {}, next->nHeight, next->GetUndoPos());
                    request.second = next;
                    // To avoid any race condition where callback would miss block connection,
                    // compare against tip and register validation interface in one sequence
                    LOCK(cs_main);
                    CBlockIndex* tip = ChainActive().Tip();
                    CBlockIndex* pindex = LookupBlockIndex(block.GetHash());
                    if (tip->GetBlockHash() == pindex->GetBlockHash()) {
                        (request.first)->UpdatedBlockTip(); // If client need to flush its state we signal tip is reached
                        (request.first)->HandleNotifications();
                        m_request_start.erase(request.first);
                    }
                }
            }
        }
    }
    // Be nice, let's requesters who need it, commit their database before to leave
    for (auto& request : m_request_start) {
        if (!request.second) continue;
        LOCK(cs_main);
        CBlockLocator locator = ::ChainActive().GetLocator(request.second);
        (request.first)->ChainStateFlushed(locator);
    }
}

void Rescan::AddRequest(interfaces::Chain::Notifications& callback, const CBlockLocator& locator)
{
    LOCK(cs_main);
    // If fork is superior at MAX_LOCATOR_SZ, rescan is going to be processed
    // from genesis. If reorg of this size happens, rescan performance hit
    // isn't the main problem.
    m_request_start[&callback] = FindForkInGlobalIndex(::ChainActive(), locator);
}

void Rescan::StartServiceRequests()
{
    threadServiceRequests = std::thread(&TraceThread<std::function<void()>>, "rescan", std::bind(&Rescan::ThreadServiceRequests, this));
}

void Rescan::InterruptServiceRequests()
{
    m_interrupt();
}

void Rescan::StopServiceRequests()
{
    if (threadServiceRequests.joinable()) {
        threadServiceRequests.join();
    }
}
