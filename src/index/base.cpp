// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <index/base.h>
#include <shutdown.h>
#include <tinyformat.h>
#include <ui_interface.h>
#include <util/system.h>
#include <validation.h>
#include <warnings.h>

constexpr char DB_BEST_BLOCK = 'B';

constexpr int64_t SYNC_LOG_INTERVAL = 30; // seconds
constexpr int64_t SYNC_LOCATOR_WRITE_INTERVAL = 30; // seconds

template<typename... Args>
static void FatalError(const char* fmt, const Args&... args)
{
    std::string strMessage = tfm::format(fmt, args...);
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        "Error: A fatal internal error occurred, see debug.log for details",
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
}

BaseIndex::DB::DB(const fs::path& path, size_t n_cache_size, bool f_memory, bool f_wipe, bool f_obfuscate) :
    CDBWrapper(path, n_cache_size, f_memory, f_wipe, f_obfuscate)
{}

bool BaseIndex::DB::ReadBestBlock(CBlockLocator& locator) const
{
    bool success = Read(DB_BEST_BLOCK, locator);
    if (!success) {
        locator.SetNull();
    }
    return success;
}

void BaseIndex::DB::WriteBestBlock(CDBBatch& batch, const CBlockLocator& locator)
{
    batch.Write(DB_BEST_BLOCK, locator);
}

BaseIndex::~BaseIndex()
{
    Interrupt();
    Stop();
}

bool BaseIndex::Init()
{
    CBlockLocator locator;
    if (!GetDB().ReadBestBlock(locator)) {
        locator.SetNull();
    }

    LOCK(cs_main);
    if (locator.IsNull()) {
        m_best_block_index = nullptr;
    } else {
        m_best_block_index = FindForkInGlobalIndex(::ChainActive(), locator);
    }
    m_synced = m_best_block_index.load() == ::ChainActive().Tip();
    return true;
}

static const CBlockIndex* NextSyncBlock(const CBlockIndex* pindex_prev) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    if (!pindex_prev) {
        return ::ChainActive().Genesis();
    }

    const CBlockIndex* pindex = ::ChainActive().Next(pindex_prev);
    if (pindex) {
        return pindex;
    }

    return ::ChainActive().Next(::ChainActive().FindFork(pindex_prev));
}

void BaseIndex::ThreadSync()
{
    const CBlockIndex* pindex = m_best_block_index.load();
    if (!m_synced) {
        auto& consensus_params = Params().GetConsensus();

        int64_t last_log_time = 0;
        int64_t last_locator_write_time = 0;
        while (true) {
            if (m_interrupt) {
                m_best_block_index = pindex;
                // No need to handle errors in Commit. If it fails, the error will be already be
                // logged. The best way to recover is to continue, as index cannot be corrupted by
                // a missed commit to disk for an advanced index state.
                Commit();
                return;
            }

            {
                LOCK(cs_main);
                const CBlockIndex* pindex_next = NextSyncBlock(pindex);
                if (!pindex_next) {
                    m_best_block_index = pindex;
                    m_synced = true;
                    // No need to handle errors in Commit. See rationale above.
                    Commit();
                    break;
                }
                if (pindex_next->pprev != pindex && !Rewind(pindex->nHeight, pindex_next->pprev->nHeight)) {
                    FatalError("%s: Failed to rewind index %s to a previous chain tip",
                               __func__, GetName());
                    return;
                }
                pindex = pindex_next;
            }

            int64_t current_time = GetTime();
            if (last_log_time + SYNC_LOG_INTERVAL < current_time) {
                LogPrintf("Syncing %s with block chain from height %d\n",
                          GetName(), pindex->nHeight);
                last_log_time = current_time;
            }

            if (last_locator_write_time + SYNC_LOCATOR_WRITE_INTERVAL < current_time) {
                m_best_block_index = pindex;
                last_locator_write_time = current_time;
                // No need to handle errors in Commit. See rationale above.
                Commit();
            }

            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, consensus_params)) {
                FatalError("%s: Failed to read block %s from disk",
                           __func__, pindex->GetBlockHash().ToString());
                return;
            }
            if (!WriteBlock(block, pindex)) {
                FatalError("%s: Failed to write block %s to index database",
                           __func__, pindex->GetBlockHash().ToString());
                return;
            }
        }
    }

    if (pindex) {
        LogPrintf("%s is enabled at height %d\n", GetName(), pindex->nHeight);
    } else {
        LogPrintf("%s is enabled\n", GetName());
    }
}

bool BaseIndex::Commit()
{
    CDBBatch batch(GetDB());
    if (!CommitInternal(batch) || !GetDB().WriteBatch(batch)) {
        return error("%s: Failed to commit latest %s state", __func__, GetName());
    }
    return true;
}

bool BaseIndex::CommitInternal(CDBBatch& batch)
{
    LOCK(cs_main);
    const CBlockIndex *pindex = ::ChainActive()[m_last_block_processed_height];
    GetDB().WriteBestBlock(batch, ::ChainActive().GetLocator(pindex));
    return true;
}

bool BaseIndex::Rewind(int forked_height, int ancestor_height)
{
    assert(forked_height == m_last_block_processed_height);

    // In the case of a reorg, ensure persisted block locator is not stale.
    m_last_block_processed_height = ancestor_height;
    if (!Commit()) {
        // If commit fails, revert the best block index to avoid corruption.
        m_last_block_processed_height = forked_height;
        return false;
    }

    return true;
}

void BaseIndex::BlockConnected(const CBlock& block, const std::vector<CTransactionRef>& txn_conflicted,
		int height, FlatFilePos block_pos)
{
    if (m_last_block_processed_height == -1 && height == 0) {
        FatalError("%s: First block connected is not the genesis block (height=%d)",
                   __func__, height);
        return;
    }
    // In the new model, if we are relying on ThreadServiceRequests to get block connection, in case of fork,
    // we are going to Rewind and restart rescan from then. If we rely on ValidationInterface (i.e we reach
    // tip at least once), we should receive BlockDisconnected event. In case of reorg, we don't overwrite
    // data committed in data base, so may have false elements but we don't miss right ones.

    if (WriteBlock(block, height, block_pos, m_last_block_processed)) {
        m_last_block_processed_height = height;
	m_last_block_processed = block.GetBlockHeader().GetHash();
    } else {
        FatalError("%s: Failed to write block %s to index",
                   __func__, block.GetBlockHeader().GetHash().ToString());
        return;
    }
    // To avoid performance hit, we flush every SYNC_LOCATOR_WRITE_INTERVAL until catch up to tip,
    // then after every block connection.
    if (m_synced) {
        int64_t current_time = GetTime();
        if (m_last_locator_write_time + SYNC_LOCATOR_WRITE_INTERVAL < current_time) {
	    m_last_locator_write_time = current_time;
            // No need to handle errors in Commit. If it fails, the error will be already be
            // logged. The best way to recover is to continue, as index cannot be corrupted by
            // a missed commit to disk for an advanced index state.
	    Commit();
	}
     } else {
	    Commit();
     }
}

void BaseIndex::BlockDisconnected(const CBlock& block, int height) {
        Commit();
	m_last_block_processed_height = height - 1;
	m_last_block_processed = block.hashPrevBlock;
	//XXX: think about blocckfilters/txindex
}

/// delete ChainStateFlushed is ok?

void BaseIndex::UpdatedBlockTip()
{
	//XXX We may still be fallen-behind but at least we don't lock chain for nothing during sync
	m_synced = true;
}

bool BaseIndex::BlockUntilSyncedToCurrentChain()
{
    AssertLockNotHeld(cs_main);

    if (!m_synced) {
        return false;
    }

    //XXX We want to be sure that event queue is drained before to go further

    LogPrintf("%s: %s is catching up on block notifications\n", __func__, GetName());
    SyncWithValidationInterfaceQueue();
    return true;
}

//XXX: dumb function to remove in next commit
bool BaseIndex::WriteBlock(const CBlock& block, const CBlockIndex *pindex)
{
	return false;
}

void BaseIndex::Interrupt()
{
    m_interrupt();
}

void BaseIndex::Start()
{
    // Need to register this ValidationInterface before running Init(), so that
    // callbacks are not missed if Init sets m_synced to true.
    RegisterValidationInterface(this);
    if (!Init()) {
        FatalError("%s: %s failed to initialize", __func__, GetName());
        return;
    }

    m_thread_sync = std::thread(&TraceThread<std::function<void()>>, GetName(),
                                std::bind(&BaseIndex::ThreadSync, this));
}

void BaseIndex::Stop()
{
    UnregisterValidationInterface(this);

    if (m_thread_sync.joinable()) {
        m_thread_sync.join();
    }
}
