// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/rescan.h>

#include <chainparams.h>
#include <primitives/block.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>

//XXX: better comment
void Rescan::ThreadServiceRequests()
{
	auto& consensus_params = Params().GetConsensus();
	while (!m_interrupt) {
		// Loop for earliest start positions.
		const CBlockIndex* min_start = nullptr;
		const CBlockIndex* ancestor = nullptr;
		for (auto& request : m_request_start) {
			//LogPrintf("Servicing request at height %d...\n", (request.second)->nHeight);
			if (!request.second) {
				m_request_start.erase(request.first);
				continue;
			}
			{
				LOCK(cs_main);
				ancestor = ChainActive().FindFork(request.second);
			}
			if (ancestor && ancestor->nHeight != (request.second)->nHeight) {
				(request.first)->Rewind(request.second->nHeight, ancestor->nHeight);
				request.second = ancestor;
			}
			if (!min_start || min_start->nHeight > (request.second)->nHeight) {
				min_start = request.second;
			}
		}
		if (min_start) {
			// Read next block and send notifications.
			CBlockIndex* next = nullptr;
			{
				LOCK(cs_main);
				next = ChainActive().Next(min_start);
			}
			if (next) {
				CBlock block;
				ReadBlockFromDisk(block, next, consensus_params);
				for (auto& request : m_request_start) {
					//XXX: do we assume reorgs ? need to clearer to avoid wallet inconsistencies
					(request.first)->BlockConnected(block, {}, next->nHeight, next->GetBlockPos());
					request.second = next;
					// To avoid any race condition where callback would miss block connection,
					// we compare against tip and register validation interface in one sequence
					LOCK(cs_main);
					CBlockIndex* tip = ChainActive().Tip();
					CBlockIndex* pindex = LookupBlockIndex(block.GetHash());
					if (tip->nHeight == pindex->nHeight) { //XXX: compare against hash to same height on forked branches
						(request.first)->UpdatedBlockTip(); // We pass pindex, we should be equal to tip
						(request.first)->HandleNotifications();
						m_request_start.erase(request.first);
					}
				}
			}
		}
	}
	// Be nice, let's requesters who need it, commit their database to leave
	for (auto& request : m_request_start) {
		if (!request.second) continue;
		LOCK(cs_main);
		CBlockLocator locator = ::ChainActive().GetLocator(request.second);
		(request.first)->ChainStateFlushed(locator);
	}
}

void Rescan::AddRequest(interfaces::Chain::Notifications& callback, const CBlockLocator& locator) {
	LOCK(cs_main);
	m_request_start[&callback] = FindForkInGlobalIndex(::ChainActive(), locator);
}

void Rescan::StartServiceRequests() {
	threadServiceRequests = std::thread(&TraceThread<std::function<void()> >, "rescan", std::bind(&Rescan::ThreadServiceRequests, this));
}

void Rescan::InterruptServiceRequests() {
	m_interrupt();
}

void Rescan::StopServiceRequests() {
	if (threadServiceRequests.joinable()) {
		threadServiceRequests.join();
	}
}
