// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <altnet/driver/context.h>
#include <altnet/driver/lightning.h>
#include <chainparamsbase.h>
#include <interfaces/init.h>
#include <interfaces/netwire.h>
#include <interfaces/validation.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <threadinterrupt.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <version.h>

#include <arpa/inet.h>
#include <chrono>
#include <endian.h>
#include <functional>
#include <cstdio>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>

using interfaces::BlockHeader;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

CLightningConnection::CLightningConnection() { }
CLightningConnection::~CLightningConnection() { }

void CLightningConnection::ThreadValidationHandler(LightningContext& ln) {

    BlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    header.nTime = 1296688602;
    header.nNonce = 2;
    header.nBits = 0x207fffff;

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        if (ln.netwire) {

            // Fetch validation engine and feed LN node
            std::vector<BlockHeader> recv_headers = ln.netwire->recvHeaders();
            if (recv_headers.size() > 0) {
                LOCK(cs_vSendMsg);
                auto it(vRecvMsg.begin());
                for (auto &it : recv_headers) {
                    vSendMsg.push_back(it);
                }
            }

            // Fetch LN node and feed validation engine.
            {
                LOCK(cs_vRecvMsg);
                if (vRecvMsg.size() > 0) {
                    for (auto &it : vRecvMsg) {
                        ln.netwire->sendHeaders(it);
                    }
                }
            }
        }
    }
}

BlockHeader readHeader(Span<const uint8_t> msg_bytes, unsigned int nHdrPos)
{
    CDataStream hdrbuf(SER_NETWORK, INIT_PROTO_VERSION);
    memcpy(&hdrbuf[nHdrPos], msg_bytes.data(), 80);
    CBlockHeader hdr;

    try {
        hdrbuf >> hdr;
    }
    catch (const std::exception&) {
        LogPrintf("Header: unable to deserialize");
        exit(0);
    }
    BlockHeader in_hdr;
    in_hdr.nVersion = hdr.nVersion;
    in_hdr.hashPrevBlock = hdr.hashPrevBlock;
    in_hdr.hashMerkleRoot = hdr.hashMerkleRoot;
    in_hdr.nTime = hdr.nTime;
    in_hdr.nNonce = hdr.nNonce;
    in_hdr.nBits = hdr.nBits;
    return in_hdr;
}


unsigned int readCmd(Span<const uint8_t> msg_bytes)
{
    CDataStream cmdbuf(SER_NETWORK, INIT_PROTO_VERSION);
    memcpy(&cmdbuf[0], msg_bytes.data(), 8);
    unsigned int cmd;

    try {
        cmdbuf >> cmd;
    }
    catch (const std::exception&) {
        LogPrintf("Header: unable to deserialize");
        exit(0);
    }
    return cmd;
}

CDataStream writeHeader(BlockHeader header) {
    CBlockHeader out_hdr;
    out_hdr.nVersion = header.nVersion;
    out_hdr.hashPrevBlock = header.hashPrevBlock;
    out_hdr.hashMerkleRoot = header.hashMerkleRoot;
    out_hdr.nTime = header.nTime;
    out_hdr.nNonce = header.nNonce;
    out_hdr.nBits = header.nBits;

    CDataStream hdrbuf(SER_NETWORK, INIT_PROTO_VERSION);
    out_hdr.Serialize(hdrbuf);

    return hdrbuf;
}

void CLightningConnection::ThreadSocketHandler() {

    struct protoent *proto;
    struct sockaddr_in sin;
    struct sockaddr_in peer_sin;
    unsigned int peer_len{0};
    int lightning_socket{0};
    int client_socket{0};
    // read state
    uint8_t cmdBuf [0x8];
    int cmd_offset{0};
    uint8_t dataBuf[0x10000];
    unsigned int data_len{0};
    int data_offset{0};
    bool in_data = false;
    unsigned char sizedesc[8];

    /* Establish socket */
    if (lightning_socket = socket(AF_INET, SOCK_STREAM, proto->p_proto) == -1) {
        return;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(8042); // hardcoded port
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Bind socket to dedicated port 8042 */
    if (bind(lightning_socket, (const struct sockaddr *)&sin, sizeof(sin)) == -1) {
        return;
    }

    if (listen(lightning_socket, 50) == -1) {
        return;
    }

    client_socket = accept(client_socket, (struct sockaddr *)&peer_sin, &peer_len);
    if (client_socket == -1) {
        return;
    }

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Recv : size | size * headers
        if (!in_data) {
            cmd_offset = recv(client_socket, (char *)cmdBuf, 8 - cmd_offset, MSG_DONTWAIT);
            if (cmd_offset == 8) {
                cmd_offset = 0;
                in_data = true;
                data_len = readCmd(Span<const uint8_t>(cmdBuf, 8));
            }
        } else {
            data_offset = recv(client_socket, (char *)dataBuf, data_len - data_offset, MSG_DONTWAIT);
            if (data_offset == 0) {
                LOCK(cs_vRecvMsg);
                for (auto i=0; i * 80 != 0; i++) {
                    auto h = readHeader(Span<const uint8_t>(dataBuf, data_len), i * 80);
                    vRecvMsg.push_back(h);
                }
                data_len = 0;
                data_offset = 0;
                in_data = false;
            }
        }

        // Send : size | size * headers
        {
            LOCK(cs_vSendMsg);
            auto batch_size = htobe64(vSendMsg.size());
            memset((char*)sizedesc, 0, 8);
            memcpy((char*)sizedesc, (char *)&batch_size, 8);
            send(lightning_socket, sizedesc, 8, MSG_NOSIGNAL | MSG_DONTWAIT);

            auto it = vSendMsg.begin();
            while (it != vSendMsg.end()) {
                CDataStream data = writeHeader(*it);
                auto nBytes = send(lightning_socket, reinterpret_cast<const char *>(data.data()), data.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                if (nBytes < 0 || nBytes != data.size()) {
                    LogPrintf("Lightning driver write failure\n");
                    break;
                }
                it++;
            }
        }
    }
}

int main(int argc, char* argv[])
{
    int exit_status;

    SetupEnvironment();

    SelectBaseParams(CBaseChainParams::MAIN);

    LogInstance().m_print_to_file = true;
    LogInstance().m_file_path = "debug-altnet-lightning.log";
    LogInstance().m_print_to_console = false;
    LogInstance().m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
    LogInstance().m_log_time_micros = DEFAULT_LOGTIMEMICROS;
    LogInstance().m_log_threadnames = DEFAULT_LOGTHREADNAMES;

    if (!LogInstance().StartLogging()) {
        throw std::runtime_error(strprintf("Could not open debug log file %s", LogInstance().m_file_path.string()));
    }

    LogPrintf("`altnet-lightning` process started!\n");

    LightningContext ln;
    CLightningConnection connection;
    auto threadValidationHandler = std::thread(&TraceThread<std::function<void()> >, "ln-validation", std::function<void()>(std::bind(&CLightningConnection::ThreadValidationHandler, std::ref(connection), std::ref(ln))));
    auto threadSocketHandler = std::thread(&TraceThread<std::function<void()> >, "ln-socket", std::function<void()>(std::bind(&CLightningConnection::ThreadSocketHandler, std::ref(connection))));

    StartAltnetLightning(ln, argc, argv, exit_status);
    if (exit_status) {
        LogPrintf("startSpawnProcess failure\n");
        return exit_status;
    }
    // This process is going to `Protocol->server()` until exit.
}
