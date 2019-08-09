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

bool BaseIndex::Init()
{
    CBlockLocator locator;
    if (!GetDB().ReadBestBlock(locator)) {
        locator.SetNull();
    }

    if (!locator.IsNull()) {
        LOCK(cs_main);
	CBlockIndex *pindex = FindForkInGlobalIndex(::ChainActive(), locator);
        m_last_block_processed_height = pindex->nHeight;
	m_synced = pindex == ::ChainActive().Tip();
    } else {
	m_synced = false;
    }
    if (!m_synced) {
	    //XXX verify how we handle null locator
        //m_chain->registerNotifications(locator);
    }
    return true;
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

void BaseIndex::ChainStateFlushed(const CBlockLocator& locator) {
    // No need to handle errors in Commit. If it fails, the error will be already be
    // logged. The best way to recover is to continue, as index cannot be corrupted by
    // a missed commit to disk for an advanced index state.
    Commit();
}

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
    //XXX: wait for commit on refactoring to clean it

    LogPrintf("%s: %s is catching up on block notifications\n", __func__, GetName());
    SyncWithValidationInterfaceQueue();
    return true;
}
