// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_RESCAN_H
#define BITCOIN_NODE_RESCAN_H

#include <optional.h>
#include <interfaces/chain.h>
#include <threadinterrupt.h>

//! Handle rescan request from Wallet clients. TODO: assumptions
class Rescan
{
private:
	std::vector<std::tuple<interfaces::Chain::Notifications *, int, int*>> m_request_rescan;

	// Read blocks in sequence starting from rescan request block hash and send
	// notifications in sequence to all requesters.
	void ThreadRescanRequests();
	std::thread threadRescanRequests;
	CThreadInterrupt m_rescan_interrupt;

public:

	//! Add rescan request, using the passed callback handler to redirect block to, starting from either
	// start time or bounded by start height - stop height.
	void AddRescan(interfaces::Chain::Notifications& callback, int64_t start_time int* start_height, int* stop_height);

	//! Start thread rescan
	void StartRescanRequests();

	//! Interrupt thread rescan
	void InterruptRescanRequests();

	//! Stop thread rescan
	void StopRescanRequests();
}
