// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/packages.h>

#include <policy/policy.h>
#include <validation.h>

#include <numeric>

bool CheckPackage(const std::vector<CTransactionRef>& txns, PackageValidationState& package_state)
{
    const unsigned int package_count = txns.size();

    // These context-free package limits can be checked before taking the mempool lock.
    if (package_count > MAX_PACKAGE_COUNT) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "too-many-transactions");
    }

    const int64_t total_size = std::accumulate(txns.cbegin(), txns.cend(), 0,
                               [](int64_t sum, const auto& tx) { return sum + GetVirtualTransactionSize(*tx); });
    // If the package only contains 1 tx, it's better to report the policy violation on individual tx size.
    if (package_count > 1 && total_size > MAX_PACKAGE_SIZE * 1000) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "too-large");
    }

    {
        std::unordered_set<uint256, SaltedTxidHasher> later_txids;
        std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                       [](const auto& tx) { return tx->GetHash(); });
        // Require the package to be sorted in order of dependency, i.e. parents appear before children.
        // An unsorted package will fail anyway on missing-inputs, but it's better to quit earlier and
        // fail on something less ambiguous (missing-inputs could also be an orphan or trying to
        // spend nonexistent coins).
       for (const auto& tx : txns) {
            for (const auto& input : tx->vin) {
                if (later_txids.find(input.prevout.hash) != later_txids.end()) {
                    // The parent is a subsequent transaction in the package.
                    return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-sorted");
                }
            }
            later_txids.erase(tx->GetHash());
       }
    }

    {
        // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
        std::unordered_set<COutPoint, SaltedOutpointHasher> inputs_seen;
        for (const auto& tx : txns) {
            for (const auto& input : tx->vin) {
                if (inputs_seen.find(input.prevout) != inputs_seen.end()) {
                    return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "conflict-in-package");
                }
            }
            // Batch-add all the inputs for a tx at a time. If we added them 1 at a time, we could
            // catch duplicate inputs within a single tx.  This is a more severe, consensus error,
            // and we want to report that from CheckTransaction instead.
            std::transform(tx->vin.cbegin(), tx->vin.cend(), std::inserter(inputs_seen, inputs_seen.end()),
                           [](const auto& input) { return input.prevout; });
        }
    }

    return true;
}
