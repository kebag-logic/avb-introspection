/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * RFC 6455 WebSocket server side. Every server→client message is a binary
 * frame containing one complete zlib (RFC 1950) stream — the browser
 * decompresses with DecompressionStream("deflate") (BE-4, OQ-2: binary
 * framing + lightweight compression).
 */
#pragma once

#include <cstdint>
#include <string>

namespace avb {

class WebSocket {
public:
    explicit WebSocket(int fd) : mFd(fd) {}

    /** Complete the 101 handshake. Returns false on socket error. */
    static bool handshake(int fd, const std::string& secWebSocketKey);

    /** Deflate `json` and send as one binary frame. */
    bool sendJsonDeflated(const std::string& json);
    bool sendClose(uint16_t code, const std::string& reason = "");

    /**
     * Poll for one client message.
     * @return 1 message received (msg/opcode set), 0 timeout, -1 closed/error.
     * Handles ping (answers pong) and close (answers close) internally —
     * those return -1 for close, 0 for ping.
     */
    int poll(std::string& msg, int& opcode, int timeoutMs);

    uint64_t bytesSent() const { return mBytesSent; }
    uint64_t messagesSent() const { return mMessagesSent; }

private:
    bool sendFrame(uint8_t opcode, const std::string& payload);
    bool readExact(uint8_t* buf, size_t n);

    int mFd;
    uint64_t mBytesSent = 0, mMessagesSent = 0;
};

} // namespace avb
