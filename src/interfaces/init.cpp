// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/altnet.h>
#include <interfaces/chain.h>
#include <interfaces/driver.h>
#include <interfaces/echo.h>
#include <interfaces/init.h>
#include <interfaces/netwire.h>
#include <interfaces/node.h>
#include <interfaces/validation.h>
#include <interfaces/wallet.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <node/context.h>
#include <primitives/block.h>
#include <util/system.h>
#include <validation.h>

namespace interfaces {

class NetwireImpl : public Netwire
{
public:
    explicit NetwireImpl(AltnetContext& altnet) : m_altnet(altnet) {}

    void sendHeaders(const interfaces::BlockHeader& header) override {
        LogPrintf("inside sendHeaders\n");
        m_altnet.validation->validateHeaders(header);
    }

    std::vector<interfaces::BlockHeader> recvHeaders() override {
        LogPrintf("inside recvHeaders\n");
        return m_altnet.validation->recvHeaders();
    }

    AltnetContext& m_altnet;
};

class ValidationImpl : public Validation
{
public:
    explicit ValidationImpl(NodeContext& node) : m_node(node) {}
    bool validateHeaders(const interfaces::BlockHeader& from_header) override
    {
        CBlockHeader header;
        header.nVersion = from_header.nVersion;
        header.hashPrevBlock = from_header.hashPrevBlock;
        header.hashMerkleRoot = from_header.hashMerkleRoot;
        header.nTime = from_header.nTime;
        header.nBits = from_header.nBits;
        header.nNonce = from_header.nNonce;

        //auto ref_header = Params().GenesisBlock().GetBlockHeader();
        //LogPrintf("header: nVersion %d prev_block %s merkle_root %s nTime %d nBits %x nNonce %x\n", header.nVersion, header.hashPrevBlock.GetHex(), header.hashMerkleRoot.GetHex(), header.nTime, header.nBits, header.nNonce);
        //LogPrintf("header: nVersion %d prev_block %s merkle_root %s nTime %d nBits %x nNonce %x\n", ref_header.nVersion, ref_header.hashPrevBlock.GetHex(), ref_header.hashMerkleRoot.GetHex(), ref_header.nTime, ref_header.nBits, ref_header.nNonce);

        std::vector<CBlockHeader> headers;
        headers.push_back(header);

        BlockValidationState state;
        m_node.chainman->ProcessNewBlockHeaders(headers, state, Params());
        if (state.IsValid()) return true;
        return false;
    }
    std::vector<interfaces::BlockHeader> recvHeaders() override {
        if (!m_sync_tip) {
            m_sync_tip = std::make_unique<CBlockHeader>(Params().GenesisBlock().GetBlockHeader());
        }
        auto headers = m_node.chainman->FetchNewBlockHeaders(*m_sync_tip);

        std::vector<BlockHeader> recv_headers;
        auto it = headers.begin();
        while (it != headers.end()) {
            CBlockHeader hdr = *it;
            BlockHeader in_hdr;
            in_hdr.nVersion = hdr.nVersion;
            in_hdr.hashPrevBlock = hdr.hashPrevBlock;
            in_hdr.hashMerkleRoot = hdr.hashMerkleRoot;
            in_hdr.nTime = hdr.nTime;
            in_hdr.nBits = hdr.nBits;
            in_hdr.nNonce = hdr.nNonce;

            recv_headers.push_back(in_hdr);

            // Save last header
            if (it + 1 == headers.end()) {
                m_sync_tip = std::make_unique<CBlockHeader>(*it);
            }
            it++;
        }
        return recv_headers;
    }
    void helloworld(const std::string& message) override
    {
        LogPrintf("ProxyClient's Validation: %s\n", message);
    }
    NodeContext& m_node;
    std::unique_ptr<CBlockHeader> m_sync_tip;
};

std::unique_ptr<Node> Init::makeNode() { return {}; }
std::unique_ptr<Chain> Init::makeChain() { return {}; }
std::unique_ptr<WalletClient> Init::makeWalletClient(Chain& chain) { return {}; }
std::unique_ptr<Echo> Init::makeEcho() { return {}; }
std::unique_ptr<Altnet> Init::makeAltnet(std::unique_ptr<Validation>) { return {}; }
std::unique_ptr<Validation> Init::makeValidation(NodeContext& node) { return std::make_unique<ValidationImpl>(node); }
std::unique_ptr<Netwire> Init::makeNetwire(AltnetContext& altnet) { return std::make_unique<NetwireImpl>(altnet); }
std::unique_ptr<Driver> Init::makeDriver(std::unique_ptr<Netwire>) { return {}; }
Ipc* Init::ipc() { return nullptr; }
} // namespace interfaces
