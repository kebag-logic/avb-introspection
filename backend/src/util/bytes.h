/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Big-endian byte reader and formatting helpers shared by all decoders.
 */
#pragma once

#include <cstdint>
#include <cstdio>
#include <span>
#include <stdexcept>
#include <string>

namespace avb {

/** Thrown when a frame is shorter than its encoding requires (PA-5). */
class ShortFrame : public std::runtime_error {
public:
    explicit ShortFrame(const std::string& what) : std::runtime_error(what) {}
};

/** Bounds-checked big-endian reader over a byte span. */
class BeReader {
public:
    explicit BeReader(std::span<const uint8_t> data) : mData(data) {}

    size_t pos() const { return mPos; }
    size_t remaining() const { return mData.size() - mPos; }

    void need(size_t n, const char* what) const {
        if (remaining() < n)
            throw ShortFrame(std::string("truncated ") + what + " (need " +
                             std::to_string(n) + " bytes, have " +
                             std::to_string(remaining()) + ")");
    }

    uint8_t u8(const char* what = "u8") {
        need(1, what);
        return mData[mPos++];
    }
    uint16_t u16(const char* what = "u16") {
        need(2, what);
        uint16_t v = (uint16_t)((mData[mPos] << 8) | mData[mPos + 1]);
        mPos += 2;
        return v;
    }
    uint32_t u32(const char* what = "u32") {
        need(4, what);
        uint32_t v = ((uint32_t)mData[mPos] << 24) | ((uint32_t)mData[mPos + 1] << 16) |
                     ((uint32_t)mData[mPos + 2] << 8) | mData[mPos + 3];
        mPos += 4;
        return v;
    }
    uint64_t u48(const char* what = "u48") {
        need(6, what);
        uint64_t v = 0;
        for (int i = 0; i < 6; ++i) v = (v << 8) | mData[mPos + i];
        mPos += 6;
        return v;
    }
    uint64_t u64(const char* what = "u64") {
        need(8, what);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | mData[mPos + i];
        mPos += 8;
        return v;
    }
    std::span<const uint8_t> bytes(size_t n, const char* what = "bytes") {
        need(n, what);
        auto s = mData.subspan(mPos, n);
        mPos += n;
        return s;
    }
    void skip(size_t n, const char* what = "padding") {
        need(n, what);
        mPos += n;
    }

private:
    std::span<const uint8_t> mData;
    size_t mPos = 0;
};

inline std::string macStr(const uint8_t* m) {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                  m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

inline std::string macStr(uint64_t m48) {
    uint8_t b[6];
    for (int i = 5; i >= 0; --i) { b[i] = (uint8_t)(m48 & 0xff); m48 >>= 8; }
    return macStr(b);
}

/** 64-bit id (entity_id, stream_id) canonical form: 0x + 16 lowercase hex. */
inline std::string idStr(uint64_t v) {
    char buf[19];
    std::snprintf(buf, sizeof buf, "0x%016llx", (unsigned long long)v);
    return buf;
}

inline std::string hexStr(uint64_t v, int digits = 0) {
    char buf[24];
    if (digits > 0)
        std::snprintf(buf, sizeof buf, "0x%0*llx", digits, (unsigned long long)v);
    else
        std::snprintf(buf, sizeof buf, "0x%llx", (unsigned long long)v);
    return buf;
}

inline std::string hexDump(std::span<const uint8_t> data) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(d[b >> 4]);
        out.push_back(d[b & 0xf]);
    }
    return out;
}

/** Fixed-size padded string field (e.g. AEM entity_name, 64 bytes, NUL padded). */
inline std::string paddedStr(std::span<const uint8_t> data) {
    size_t end = data.size();
    while (end > 0 && data[end - 1] == 0) --end;
    std::string s;
    for (size_t i = 0; i < end; ++i) {
        uint8_t c = data[i];
        s.push_back((c >= 0x20 && c < 0x7f) ? (char)c : '.');
    }
    return s;
}

} // namespace avb
