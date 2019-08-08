// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_SYNC_H
#define BITCOIN_NODE_SYNC_H

#include <interfaces/chain.h>
#include <threadinterrupt.h>

class CBlockIndex;

//! Wallets can be fallen-behind chain tip at restart. They need
//! to learn about blocks connected during their shutdown to update their
//! internal states accordingly. If we have many wallets, each
//! of them is going to read the same resync range repeatedly out of order
//! instead of just once in order. To avoid that, Sync accept
//! sync request at initialization and fulfill all of them in a thread
//! ThreadServiceRequests started/stopped at init/shutdown sequences.
class Sync
{
private:
    std::map<interfaces::Chain::Notifications *, const CBlockIndex*> m_request_start;
    //TODO: Future plan is to use a thread pool with multiple workers to process
    // rescan requests in parallel beyond clients loading
    std::thread threadServiceRequests;
    CThreadInterrupt m_interrupt;

    //! Read blocks in sequence, consolidating sync requests and send notifications in sequence
    //! to all requesters.
    void ThreadServiceRequests();

public:
    //! Add sync request, using the passed callback handler to redirect block to, starting from
    //! locator. If fork is detected, ask client to rollback its state by calling successivily
    //! BlockDisconnected.
    void AddRequest(interfaces::Chain::Notifications& callback, const CBlockLocator& locator);

    //! Start thread worker to replay blocks for registered requester.
    void StartServiceRequests();

    //! Interrupt thread worker replaying blocks.
    void InterruptServiceRequests();

    //! Stop thread worker replaying blocks.
    void StopServiceRequests();
};

#endif // BITCOIN_NODE_SYNC_H
