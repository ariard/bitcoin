// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <drivers/clightning.h>

#include <altnet.h>
#include <drivers.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

bool ClightningDriver::Warmup() {
    struct protoent *proto;
    struct sockaddr_in sin;

    LogPrint(BCLog::ALTSTACK, "Clightning - Warmup\n");
    if ((proto = getprotobyname("tcp")) == 0)
        return false;

    /* Establish socket */
    if ((driver_socket = socket(AF_INET, SOCK_STREAM, proto->p_proto)) == -1) {
        LogPrint(BCLog::ALTSTACK, "Clightning - Bridge socket failure\n");
        return false;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(hardcoded_port);
    sin.sin_addr.s_addr = inet_addr(hardcoded_addr);

    /* Connect to bridge */
    if (connect(driver_socket, (const struct sockaddr *)&sin, sizeof(sin)) == -1) {
        LogPrint(BCLog::ALTSTACK, "Clightning - Bridge connect failure\n");
        return false;
    }

    offset = 0;
    return true;
}

bool ClightningDriver::Flush() {
    auto it = vSendMsg.begin();

    while (it != vSendMsg.end()) {
        const auto &data = *it;
        int nBytes = 0;
        nBytes = send(driver_socket, reinterpret_cast<const char*>(data.data()) + offset, data.size() - offset, MSG_NOSIGNAL | MSG_DONTWAIT);

        if (nBytes > 0) {
            offset += nBytes;
            if (offset == data.size()) {
                offset = 0;
                it++;
            } else {
                break;
            }
        } else {
            if (nBytes < 0) {
                LogPrint(BCLog::ALTSTACK, "Cligthning - Bridge send failure\n");
                return false;
            }
        }
    }

    vSendMsg.erase(vSendMsg.begin(), it);
    return true;
}

bool ClightningDriver::Receive(CAltMsg& msg) {
    char pchBuf[0x10000];
    int nBytes = 0;
    nBytes = recv(driver_socket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
    if (nBytes > 0) {
        msg.m_recv.resize(256 * 1024);
        memcpy(&msg.m_recv[0], pchBuf, 256 * 1024);
    } else {
        //LogPrint(BCLog::ALTSTACK, "Cligtning - Bridge receive failure\n");
        return false;
    }
    return true;
}

bool ClightningDriver::Listen(uint32_t potential_node_id) {
    return true;
}

bool ClightningDriver::Send(uint32_t node_id, std::vector<unsigned char> data) {
    vSendMsg.push_back(std::move(data));
    return true;
}

TransportCapabilities ClightningDriver::GetCapabilities() {
    return TransportCapabilities(true, true, true);
}
