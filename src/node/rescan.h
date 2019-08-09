// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_RESCAN_H
#define BITCOIN_NODE_RESCAN_H

#include <interfaces/chain.h>
#include <threadinterrupt.h>

class CBlockIndex;

//! Wallets or indexes can be fallen-behind chain tip at restart. They need
//! to learn about blocks connected during their shutdown to update their
//! internal states accordingly. If we have many wallets or indexes, each
//! of them is going to read the same scan range repeatedly out of order
//! instead of just once in order. To avoid that, Rescan accept
//! rescan request at initialization and fulfill all of them in a thread
//! ThreadRescan spawned by ChainImpl.
class Rescan
{
private:
	std::map<interfaces::Chain::Notifications*, const CBlockIndex*> m_request_start;
	std::thread threadServiceRequests;
	CThreadInterrupt m_interrupt;

	//! Read blocks in sequence, consolidating rescan requests and send notifications in sequence
	//! to all.
	void	ThreadServiceRequests();
public:
	//! Add rescan request, using the passed callback handler to reditect block to, starting from
	//! locator.
	void	AddRequest(interfaces::Chain::Notifications& callback, const CBlockLocator& locator);

	//! Start thread worker to replay blocks for registered requester.
	//TODO: we may use a thread pool with master - multiple worker
	void    StartServiceRequests();

	//! Interrupt thread worker replaying blocks.
	void	InterruptServiceRequests();

	//! Stop thread worker replaying blocks.
	void	StopServiceRequests();
};

#endif // BITCOIN_NODE_RESCAN_H
