// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <txrequest.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <algorithm>
#include <functional>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(txrequest_tests, BasicTestingSetup)

namespace {

constexpr std::chrono::microseconds MIN_TIME = std::chrono::microseconds::min();
constexpr std::chrono::microseconds MAX_TIME = std::chrono::microseconds::max();
constexpr std::chrono::microseconds MICROSECOND = std::chrono::microseconds{1};
constexpr std::chrono::microseconds NO_TIME = std::chrono::microseconds{0};

/** An Action is a function to call at a particular (simulated) timestamp. */
using Action = std::pair<std::chrono::microseconds, std::function<void()>>;

/** Object that stores actions from multiple interleaved scenarios, and data shared across them.
 *
 * The Scenario below is used to fill this.
 */
struct Runner
{
    /** The TxRequestTracker being tested. */
    TxRequestTracker txrequest;

    /** List of actions to be executed (in order of increasing timestamp). */
    std::vector<Action> actions;

    /** Which node ids have been assigned already (to prevent reuse). */
    std::set<NodeId> peerset;

    /** Which txhashes have been assigned already (to prevent reuse). */
    std::set<uint256> txhashset;
};

std::chrono::microseconds RandomTime8s() { return std::chrono::microseconds{1 + InsecureRandBits(23)}; }
std::chrono::microseconds RandomTime1y() { return std::chrono::microseconds{1 + InsecureRandBits(45)}; }

/** A proxy for a Runner that helps build a sequence of consecutive test actions on a TxRequestTracker.
 *
 * Each Scenario is a proxy through which actions for the (sequential) execution of various tests are added to a
 * Runner. The actions from multiple scenarios are then run concurrently, resulting in these tests being performed
 * against a TxRequestTracker in parallel. Every test has its own unique txhashes and NodeIds which are not
 * reused in other tests, and thus they should be independent from each other. Running them in parallel however
 * means that we verify the behavior (w.r.t. one test's txhashes and NodeIds) even when the state of the data
 * structure is more complicated due to the presence of other tests.
 */
class Scenario
{
    Runner& m_runner;
    std::chrono::microseconds m_now;
    std::string m_testname;

public:
    Scenario(Runner& runner, std::chrono::microseconds starttime) : m_runner(runner), m_now(starttime) {}

    /** Set a name for the current test, to give more clear error messages. */
    void SetTestName(std::string testname)
    {
        m_testname = std::move(testname);
    }

    /** Advance this Scenario's time; this affects the timestamps newly scheduled events get. */
    void AdvanceTime(std::chrono::microseconds amount)
    {
        assert(amount.count() >= 0);
        m_now += amount;
    }

    /** Schedule a ForgetTxHash call at the Scheduler's current time. */
    void ForgetTxHash(const uint256& txhash)
    {
        auto& runner = m_runner;
        runner.actions.emplace_back(m_now, [=,&runner]() {
            runner.txrequest.ForgetTxHash(txhash);
            runner.txrequest.SanityCheck();
        });
    }

    /** Schedule a ReceivedInv call at the Scheduler's current time. */
    void ReceivedInv(NodeId peer, const GenTxid& gtxid, bool pref, std::chrono::microseconds reqtime = MIN_TIME)
    {
        auto& runner = m_runner;
        runner.actions.emplace_back(m_now, [=,&runner]() {
            runner.txrequest.ReceivedInv(peer, gtxid, pref, reqtime);
            runner.txrequest.SanityCheck();
        });
    }

    /** Schedule a DisconnectedPeer call at the Scheduler's current time. */
    void DisconnectedPeer(NodeId peer)
    {
        auto& runner = m_runner;
        runner.actions.emplace_back(m_now, [=,&runner]() {
            runner.txrequest.DisconnectedPeer(peer);
            runner.txrequest.SanityCheck();
        });
    }

    /** Schedule a RequestedTx call at the Scheduler's current time. */
    void RequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds exptime)
    {
        auto& runner = m_runner;
        runner.actions.emplace_back(m_now, [=,&runner]() {
            runner.txrequest.RequestedTx(peer, txhash, exptime);
            runner.txrequest.SanityCheck();
        });
    }

    /** Schedule a ReceivedResponse call at the Scheduler's current time. */
    void ReceivedResponse(NodeId peer, const uint256& txhash)
    {
        auto& runner = m_runner;
        runner.actions.emplace_back(m_now, [=,&runner]() {
            runner.txrequest.ReceivedResponse(peer, txhash);
            runner.txrequest.SanityCheck();
        });
    }

    /** Schedule calls to verify the TxRequestTracker's state at the Scheduler's current time.
     *
     * @param peer       The peer whose state will be inspected.
     * @param expected   The expected return value for GetRequestable(peer)
     * @param candidates The expected return value CountCandidates(peer)
     * @param inflight   The expected return value CountInFlight(peer)
     * @param completed  The expected return value of Count(peer), minus candidates and inflight.
     * @param checkname  An arbitrary string to include in error messages, for test identificatrion.
     */
    void Check(NodeId peer, const std::vector<GenTxid>& expected, size_t candidates, size_t inflight,
        size_t completed, const std::string& checkname = "")
    {
        const auto comment = m_testname + " " + checkname;
        auto& runner = m_runner;
        const auto now = m_now;
        runner.actions.emplace_back(m_now, [=,&runner]() {
            auto ret = runner.txrequest.GetRequestable(peer, now);
            runner.txrequest.SanityCheck();
            runner.txrequest.PostGetRequestableSanityCheck(now);
            size_t total = candidates + inflight + completed;
            size_t real_total = runner.txrequest.Count(peer);
            size_t real_candidates = runner.txrequest.CountCandidates(peer);
            size_t real_inflight = runner.txrequest.CountInFlight(peer);
            BOOST_CHECK_MESSAGE(real_total == total, strprintf("[" + comment + "] total %i (%i expected)", real_total, total));
            BOOST_CHECK_MESSAGE(real_inflight == inflight, strprintf("[" + comment + "] inflight %i (%i expected)", real_inflight, inflight));
            BOOST_CHECK_MESSAGE(real_candidates == candidates, strprintf("[" + comment + "] candidates %i (%i expected)", real_candidates, candidates));
            BOOST_CHECK_MESSAGE(ret == expected, "[" + comment + "] mismatching requestables");
        });
    }

    /** Generate a random txhash, whose priorities for certain peers are constrained.
     *
     * For example, NewTxHash({{p1,p2,p3},{p2,p4,p5}}) will generate a txhash T such that both:
     *  - priority(p1,T) < priority(p2,T) < priority(p3,T)
     *  - priority(p2,T) < priority(p4,T) < priority(p5,T)
     * where priority is the predicted internal TxRequestTracker's priority, assuming all announcements
     * are within the same preferredness class.
     */
    uint256 NewTxHash(const std::vector<std::vector<NodeId>>& orders = {})
    {
        uint256 ret;
        bool ok;
        do {
            ret = InsecureRand256();
            ok = true;
            for (const auto& order : orders) {
                for (size_t pos = 1; pos < order.size(); ++pos) {
                    uint64_t prio_prev = m_runner.txrequest.ComputePriority(ret, order[pos - 1], true);
                    uint64_t prio_cur = m_runner.txrequest.ComputePriority(ret, order[pos], true);
                    if (prio_prev >= prio_cur) {
                        ok = false;
                        break;
                    }
                }
                if (!ok) break;
            }
            if (ok) {
                ok = m_runner.txhashset.insert(ret).second;
            }
        } while(!ok);
        return ret;
    }

    /** Generate a random GenTxid; the txhash follows NewTxHash; the is_wtxid flag is random. */
    GenTxid NewGTxid(const std::vector<std::vector<NodeId>>& orders = {})
    {
        return {InsecureRandBool(), NewTxHash(orders)};
    }

    /** Generate a new random NodeId to use as peer. The same NodeId is never returned twice
     *  (across all Scenarios combined). */
    NodeId NewPeer()
    {
        bool ok;
        NodeId ret;
        do {
            ret = InsecureRandBits(63);
            ok = m_runner.peerset.insert(ret).second;
        } while(!ok);
        return ret;
    }

    std::chrono::microseconds Now() const { return m_now; }
};

/** Add to scenario a test with a single tx announced by a single peer.
 *
 * config is an integer between 0 and 31, which controls which variant of the test is used.
 */
void BuildSingleTest(Scenario& scenario, int config)
{
    auto peer = scenario.NewPeer();
    auto gtxid = scenario.NewGTxid();
    bool immediate = config & 1;
    bool preferred = config & 2;
    auto delay = immediate ? NO_TIME : RandomTime8s();

    scenario.SetTestName(strprintf("Single(config=%i)", config));

    // Receive an announcement, either immediately requestable or delayed.
    scenario.ReceivedInv(peer, gtxid, preferred, immediate ? MIN_TIME : scenario.Now() + delay);
    if (immediate) {
        scenario.Check(peer, {gtxid}, 1, 0, 0, "s1");
    } else {
        scenario.Check(peer, {}, 1, 0, 0, "s2");
        scenario.AdvanceTime(delay - MICROSECOND);
        scenario.Check(peer, {}, 1, 0, 0, "s3");
        scenario.AdvanceTime(MICROSECOND);
        scenario.Check(peer, {gtxid}, 1, 0, 0, "s4");
    }

    if (config >> 3) { // We'll request the transaction
        scenario.AdvanceTime(RandomTime8s());
        auto expiry = RandomTime8s();
        scenario.Check(peer, {gtxid}, 1, 0, 0, "s5");
        scenario.RequestedTx(peer, gtxid.GetHash(), scenario.Now() + expiry);
        scenario.Check(peer, {}, 0, 1, 0, "s6");

        if ((config >> 3) == 1) { // The request will time out
            scenario.AdvanceTime(expiry - MICROSECOND);
            scenario.Check(peer, {}, 0, 1, 0, "s7");
            scenario.AdvanceTime(MICROSECOND);
            scenario.Check(peer, {}, 0, 0, 0, "s8");
            return;
        } else {
            scenario.AdvanceTime(std::chrono::microseconds{InsecureRandRange(expiry.count())});
            scenario.Check(peer, {}, 0, 1, 0, "s9");
            if ((config >> 3) == 3) { // A reponse will arrive for the transaction
                scenario.ReceivedResponse(peer, gtxid.GetHash());
                scenario.Check(peer, {}, 0, 0, 0, "s10");
                return;
            }
        }
    }

    if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
    if (config & 4) { // The peer will go offline
        scenario.DisconnectedPeer(peer);
    } else { // The transaction is no longer needed
        scenario.ForgetTxHash(gtxid.GetHash());
    }
    scenario.Check(peer, {}, 0, 0, 0, "s11");
}

/** Add to scenario a test with a single tx announced by two peers, to verify the
 *  right peer is selected for requests.
 *
 * config is an integer between 0 and 63, which controls which variant of the test is used.
 */
void BuildPriorityTest(Scenario& scenario, int config)
{
    scenario.SetTestName(strprintf("Priority(config=%i)", config));

    // Three peers. They will announce in order.
    auto peer1 = scenario.NewPeer(), peer2 = scenario.NewPeer();
    // Construct a transaction that under random rules would be preferred by peer2 or peer1,
    // depending on configuration.
    bool prio1 = config & 1;
    auto gtxid = prio1 ? scenario.NewGTxid({{peer1, peer2}}) : scenario.NewGTxid({{peer2, peer1}});
    bool pref1 = config & 2, pref2 = config & 4;

    scenario.ReceivedInv(peer1, gtxid, pref1, MIN_TIME);
    scenario.Check(peer1, {gtxid}, 1, 0, 0, "p1");
    if (InsecureRandBool()) {
        scenario.AdvanceTime(RandomTime8s());
        scenario.Check(peer1, {gtxid}, 1, 0, 0, "p2");
    }

    scenario.ReceivedInv(peer2, gtxid, pref2, MIN_TIME);
    bool stage2_prio =
        // At this point, peer2 will be given priority if:
        // - It is preferred and peer1 is not
        (pref2 && !pref1) ||
        // - They're in the same preference class,
        //   and the randomized priority favors peer2 over peer1.
        (pref1 == pref2 && !prio1);
    uint64_t priopeer = stage2_prio ? peer2 : peer1, otherpeer = stage2_prio ? peer1 : peer2;
    scenario.Check(otherpeer, {}, 1, 0, 0, "p3");
    scenario.Check(priopeer, {gtxid}, 1, 0, 0, "p4");
    if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
    scenario.Check(otherpeer, {}, 1, 0, 0, "p5");
    scenario.Check(priopeer, {gtxid}, 1, 0, 0, "p6");

    // We possibly request from the selected peer.
    if (config & 8) {
        scenario.RequestedTx(priopeer, gtxid.GetHash(), MAX_TIME);
        scenario.Check(priopeer, {}, 0, 1, 0, "p7");
        scenario.Check(otherpeer, {}, 1, 0, 0, "p8");
        if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
    }

    // The peer which was selected (or requested from) now goes offline, or a NOTFOUND is received from them.
    if (config & 16) {
        scenario.DisconnectedPeer(priopeer);
    } else {
        scenario.ReceivedResponse(priopeer, gtxid.GetHash());
    }
    if (config & 32) scenario.AdvanceTime(RandomTime8s());
    scenario.Check(priopeer, {}, 0, 0, !(config & 16), "p8");
    scenario.Check(otherpeer, {gtxid}, 1, 0, 0, "p9");
    if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());

    // Now the other peer goes offline.
    scenario.DisconnectedPeer(otherpeer);
    if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
    scenario.Check(peer1, {}, 0, 0, 0, "p10");
    scenario.Check(peer2, {}, 0, 0, 0, "p11");
}

/** Add to scenario a randomized test in which N peers announce the same transaction, to verify
 *  the order in which they are requested.
 */
void BuildBigPriorityTest(Scenario& scenario, int peers)
{
    scenario.SetTestName(strprintf("BigPriority(peers=%i)", peers));

    // We will have N peers announce the same transaction.
    std::map<NodeId, bool> preferred;
    std::vector<NodeId> pref_peers, npref_peers;
    int num_pref = InsecureRandRange(peers + 1) ; // Some preferred, ...
    int num_npref = peers - num_pref; // some not preferred.
    for (int i = 0; i < num_pref; ++i) {
        pref_peers.push_back(scenario.NewPeer());
        preferred[pref_peers.back()] = true;
    }
    for (int i = 0; i < num_npref; ++i) {
        npref_peers.push_back(scenario.NewPeer());
        preferred[npref_peers.back()] = false;
    }
    // Make a list of all peers, in order of intended request order (concatenation of pref_peers and npref_peers).
    std::vector<NodeId> request_order;
    for (int i = 0; i < num_pref; ++i) request_order.push_back(pref_peers[i]);
    for (int i = 0; i < num_npref; ++i) request_order.push_back(npref_peers[i]);

    // Determine the announcement order randomly.
    std::vector<NodeId> announce_order = request_order;
    Shuffle(announce_order.begin(), announce_order.end(), g_insecure_rand_ctx);

    // Find a gtxid whose txhash prioritization is consistent with the required ordering within pref_peers and
    // within npref_peers.
    auto gtxid = scenario.NewGTxid({pref_peers, npref_peers});

    // Decide reqtimes in opposite order of the expected request order. This means that as time passes we expect the
    // to-be-requested-from-peer will change every time a subsequent reqtime is passed.
    std::map<NodeId, std::chrono::microseconds> reqtimes;
    auto reqtime = scenario.Now();
    for (int i = peers - 1; i >= 0; --i) {
        reqtime += RandomTime8s();
        reqtimes[request_order[i]] = reqtime;
    }

    // Actually announce from all peers simultaneously (but in announce_order).
    for (const auto peer : announce_order) {
        scenario.ReceivedInv(peer, gtxid, preferred[peer], reqtimes[peer]);
    }
    for (const auto peer : announce_order) {
        scenario.Check(peer, {}, 1, 0, 0, "b1");
    }

    // Let time pass and observe the to-be-requested-from peer change, from nonpreferred to preferred, and from
    // high priority to low priority within each class.
    for (int i = peers - 1; i >= 0; --i) {
        scenario.AdvanceTime(reqtimes[request_order[i]] - scenario.Now() - MICROSECOND);
        scenario.Check(request_order[i], {}, 1, 0, 0, "b2");
        scenario.AdvanceTime(MICROSECOND);
        scenario.Check(request_order[i], {gtxid}, 1, 0, 0, "b3");
    }

    // Peers now in random order go offline, or send NOTFOUNDs. At every point in time the new to-be-requested-from
    // peer should be the best remaining one, so verify this after every response.
    for (int i = 0; i < peers; ++i) {
        if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
        const int pos = InsecureRandRange(request_order.size());
        const auto peer = request_order[pos];
        request_order.erase(request_order.begin() + pos);
        if (InsecureRandBool()) {
            scenario.DisconnectedPeer(peer);
            scenario.Check(peer, {}, 0, 0, 0, "b4");
        } else {
            scenario.ReceivedResponse(peer, gtxid.GetHash());
            scenario.Check(peer, {}, 0, 0, request_order.size() > 0, "b5");
        }
        if (request_order.size()) {
            scenario.Check(request_order[0], {gtxid}, 1, 0, 0, "b6");
        }
    }

    // Everything is gone in the end.
    for (const auto peer : announce_order) {
        scenario.Check(peer, {}, 0, 0, 0, "b7");
    }
}

/** Add to scenario a test with one peer announcing two transactions, to verify they are
 *  fetched in announcement order. */
void BuildRequestOrderTest(Scenario& scenario, int config)
{
    scenario.SetTestName(strprintf("RequestOrder(config=%i)", config));

    auto peer = scenario.NewPeer();
    auto gtxid1 = scenario.NewGTxid();
    auto gtxid2 = scenario.NewGTxid();

    auto reqtime2 = scenario.Now() + RandomTime8s();
    auto reqtime1 = reqtime2 + RandomTime8s();

    scenario.ReceivedInv(peer, gtxid1, config & 1, reqtime1);
    // Simulate time going backwards by giving the second announcement an earlier reqtime.
    scenario.ReceivedInv(peer, gtxid2, config & 2, reqtime2);

    scenario.AdvanceTime(reqtime2 - MICROSECOND - scenario.Now());
    scenario.Check(peer, {}, 2, 0, 0, "o1");
    scenario.AdvanceTime(MICROSECOND);
    scenario.Check(peer, {gtxid2}, 2, 0, 0, "o2");
    scenario.AdvanceTime(reqtime1 - MICROSECOND - scenario.Now());
    scenario.Check(peer, {gtxid2}, 2, 0, 0, "o3");
    scenario.AdvanceTime(MICROSECOND);
    // Even with time going backwards in between announcements, the return value of GetRequestable is in
    // announcement order.
    scenario.Check(peer, {gtxid1, gtxid2}, 2, 0, 0, "o4");

    scenario.DisconnectedPeer(peer);
    scenario.Check(peer, {}, 0, 0, 0, "o5");
}

/** Add to scenario a test thats verifies behavior related to both txid and wtxid with the same
    hash being announced.
*/
void BuildWtxidTest(Scenario& scenario, int config)
{
    scenario.SetTestName(strprintf("Wtxid(config=%i)", config));

    auto peerT = scenario.NewPeer();
    auto peerW = scenario.NewPeer();
    auto txhash = scenario.NewTxHash();
    GenTxid txid{false, txhash};
    GenTxid wtxid{true, txhash};

    auto reqtimeT = InsecureRandBool() ? MIN_TIME : scenario.Now() + RandomTime8s();
    auto reqtimeW = InsecureRandBool() ? MIN_TIME : scenario.Now() + RandomTime8s();

    // Announce txid first or wtxid first.
    if (config & 1) {
        scenario.ReceivedInv(peerT, txid, config & 2, reqtimeT);
        if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
        scenario.ReceivedInv(peerW, wtxid, !(config & 2), reqtimeW);
    } else {
        scenario.ReceivedInv(peerW, wtxid, !(config & 2), reqtimeW);
        if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
        scenario.ReceivedInv(peerT, txid, config & 2, reqtimeT);
    }

    // Let time pass if needed, and check that the preferred announcement (txid or wtxid)
    // is correctly to-be-requested (and with the correct wtxidness).
    auto max_reqtime = std::max(reqtimeT, reqtimeW);
    if (max_reqtime > scenario.Now()) scenario.AdvanceTime(max_reqtime - scenario.Now());
    if (config & 2) {
        scenario.Check(peerT, {txid}, 1, 0, 0, "w1");
        scenario.Check(peerW, {}, 1, 0, 0, "w2");
    } else {
        scenario.Check(peerT, {}, 1, 0, 0, "w3");
        scenario.Check(peerW, {wtxid}, 1, 0, 0, "w4");
    }

    // If a good transaction with either that hash as wtxid or txid arrives, both
    // announcements are gone.
    if (InsecureRandBool()) scenario.AdvanceTime(RandomTime8s());
    scenario.ForgetTxHash(txhash);
    scenario.Check(peerT, {}, 0, 0, 0, "w5");
    scenario.Check(peerW, {}, 0, 0, 0, "w6");
}

void TestInterleavedScenarios()
{
    // Create a list of functions which add tests to scenarios.
    std::vector<std::function<void(Scenario&)>> builders;
    // Add instances of every test, for every configuration.
    for (int config = 0; config < 4; ++config) {
        builders.emplace_back([config](Scenario& scenario){ BuildWtxidTest(scenario, config); });
    }
    for (int config = 0; config < 4; ++config) {
        builders.emplace_back([config](Scenario& scenario){ BuildRequestOrderTest(scenario, config); });
    }
    for (int config = 0; config < 32; ++config) {
        builders.emplace_back([config](Scenario& scenario){ BuildSingleTest(scenario, config); });
    }
    for (int config = 0; config < 64; ++config) {
        builders.emplace_back([config](Scenario& scenario){ BuildPriorityTest(scenario, config); });
    }
    for (int peers = 1; peers <= 8; ++peers) {
        for (int i = 0; i < 10; ++i) {
            builders.emplace_back([peers](Scenario& scenario){ BuildBigPriorityTest(scenario, peers); });
        }
    }
    // Randomly shuffle all those functions.
    Shuffle(builders.begin(), builders.end(), g_insecure_rand_ctx);

    Runner runner;
    auto starttime = RandomTime1y();
    // Construct many scenarios, and run (up to) 10 randomly-chosen tests consecutively in each.
    while (builders.size()) {
        // Introduce some variation in the start time of each scenario, so they don't all start off
        // concurrently, but get a more random interleaving.
        auto scenario_start = starttime + RandomTime8s() + RandomTime8s() + RandomTime8s();
        Scenario scenario(runner, scenario_start);
        for (int j = 0; builders.size() && j < 10; ++j) {
            builders.back()(scenario);
            builders.pop_back();
        }
    }
    // Sort all the actions from all those scenarios chronologically, resulting in the actions from
    // distinct scenarios to become interleaved. Use stable_sort so that actions from one scenario
    // aren't reordered w.r.t. each other.
    std::stable_sort(runner.actions.begin(), runner.actions.end(), [](const Action& a1, const Action& a2) {
        return a1.first < a2.first;
    });

    // Run all actions from all scenarios, in order.
    for (auto& action : runner.actions) {
        action.second();
    }
}

}  // namespace

BOOST_AUTO_TEST_CASE(TxRequestTest)
{
    for (int i = 0; i < 5; ++i) {
        TestInterleavedScenarios();
    }
}

BOOST_AUTO_TEST_SUITE_END()
