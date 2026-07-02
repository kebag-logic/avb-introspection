/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "websocket.h"

#include <poll.h>
#include <sys/socket.h>
#include <zlib.h>

#include <vector>

#include "../util/crypto_util.h"

namespace avb {

namespace {

bool sendAll(int fd, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

constexpr size_t kMaxClientPayload = 1 * 1024 * 1024;

} // namespace

bool WebSocket::handshake(int fd, const std::string& secWebSocketKey) {
    std::string resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " +
        wsAcceptKey(secWebSocketKey) + "\r\n\r\n";
    return sendAll(fd, (const uint8_t*)resp.data(), resp.size());
}

bool WebSocket::sendFrame(uint8_t opcode, const std::string& payload) {
    std::vector<uint8_t> hdr;
    hdr.push_back(0x80 | opcode); // FIN + opcode
    size_t len = payload.size();
    if (len < 126) {
        hdr.push_back((uint8_t)len);
    } else if (len <= 0xffff) {
        hdr.push_back(126);
        hdr.push_back((uint8_t)(len >> 8));
        hdr.push_back((uint8_t)len);
    } else {
        hdr.push_back(127);
        for (int i = 7; i >= 0; --i) hdr.push_back((uint8_t)(len >> (i * 8)));
    }
    if (!sendAll(mFd, hdr.data(), hdr.size())) return false;
    if (!sendAll(mFd, (const uint8_t*)payload.data(), payload.size()))
        return false;
    mBytesSent += hdr.size() + payload.size();
    return true;
}

bool WebSocket::sendJsonDeflated(const std::string& json) {
    uLongf bound = compressBound((uLong)json.size());
    std::string out;
    out.resize(bound);
    // Z_BEST_SPEED: OQ-2 asked for a lightweight algorithm — favour CPU over
    // ratio; zlib format so browsers can use DecompressionStream("deflate").
    if (compress2((Bytef*)out.data(), &bound, (const Bytef*)json.data(),
                  (uLong)json.size(), Z_BEST_SPEED) != Z_OK)
        return false;
    out.resize(bound);
    if (!sendFrame(0x2, out)) return false;
    mMessagesSent++;
    return true;
}

bool WebSocket::sendClose(uint16_t code, const std::string& reason) {
    std::string payload;
    payload.push_back((char)(code >> 8));
    payload.push_back((char)(code & 0xff));
    payload += reason;
    return sendFrame(0x8, payload);
}

bool WebSocket::readExact(uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = ::recv(mFd, buf + off, n - off, 0);
        if (r <= 0) return false;
        off += (size_t)r;
    }
    return true;
}

int WebSocket::poll(std::string& msg, int& opcode, int timeoutMs) {
    pollfd pfd{mFd, POLLIN, 0};
    int pr = ::poll(&pfd, 1, timeoutMs);
    if (pr == 0) return 0;
    if (pr < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) return -1;

    uint8_t h[2];
    if (!readExact(h, 2)) return -1;
    opcode = h[0] & 0x0f;
    bool masked = (h[1] & 0x80) != 0;
    uint64_t len = h[1] & 0x7f;
    if (len == 126) {
        uint8_t e[2];
        if (!readExact(e, 2)) return -1;
        len = ((uint64_t)e[0] << 8) | e[1];
    } else if (len == 127) {
        uint8_t e[8];
        if (!readExact(e, 8)) return -1;
        len = 0;
        for (int i = 0; i < 8; ++i) len = (len << 8) | e[i];
    }
    if (len > kMaxClientPayload) return -1;
    uint8_t mask[4] = {0, 0, 0, 0};
    if (masked && !readExact(mask, 4)) return -1;

    msg.resize((size_t)len);
    if (len && !readExact((uint8_t*)msg.data(), (size_t)len)) return -1;
    if (masked)
        for (size_t i = 0; i < msg.size(); ++i)
            msg[i] = (char)((uint8_t)msg[i] ^ mask[i % 4]);

    switch (opcode) {
    case 0x8: // close — echo and report
        sendFrame(0x8, msg.substr(0, 2));
        return -1;
    case 0x9: // ping — answer pong, treat as no message
        sendFrame(0xA, msg);
        return 0;
    case 0xA: // pong
        return 0;
    default:
        return 1;
    }
}

} // namespace avb
