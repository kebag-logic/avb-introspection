/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * SHA-1 and base64 — needed only for the RFC 6455 WebSocket handshake.
 * Password hashing uses libsodium (Argon2id), not this file.
 */
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace avb {

std::array<uint8_t, 20> sha1(std::span<const uint8_t> data);
std::string base64(std::span<const uint8_t> data);

/** Sec-WebSocket-Accept value for a Sec-WebSocket-Key header. */
std::string wsAcceptKey(const std::string& clientKey);

} // namespace avb
