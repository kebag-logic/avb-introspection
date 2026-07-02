/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "json.h"

#include <cmath>
#include <cstdio>
#include <cstring>

namespace avb {

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            } else {
                out += (char)c;
            }
        }
    }
    out += '"';
    return out;
}

void JsonWriter::appendEscaped(const std::string& s) { mOut += jsonEscape(s); }

JsonWriter& JsonWriter::value(double v) {
    comma();
    if (!std::isfinite(v)) {
        mOut += "null";
        return *this;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.9g", v);
    mOut += buf;
    return *this;
}

namespace {

class Parser {
public:
    Parser(const char* p, const char* end) : mP(p), mEnd(end) {}

    bool parseValue(JsonValue& out, int depth) {
        if (depth > 64) return fail("nesting too deep");
        ws();
        if (mP >= mEnd) return fail("unexpected end");
        switch (*mP) {
        case '{': return parseObject(out, depth);
        case '[': return parseArray(out, depth);
        case '"': out.type = JsonValue::Type::String; return parseString(out.str);
        case 't':
            if (lit("true")) { out.type = JsonValue::Type::Bool; out.boolean = true; return true; }
            return fail("bad literal");
        case 'f':
            if (lit("false")) { out.type = JsonValue::Type::Bool; out.boolean = false; return true; }
            return fail("bad literal");
        case 'n':
            if (lit("null")) { out.type = JsonValue::Type::Null; return true; }
            return fail("bad literal");
        default: return parseNumber(out);
        }
    }

    void ws() {
        while (mP < mEnd && (*mP == ' ' || *mP == '\t' || *mP == '\n' || *mP == '\r')) ++mP;
    }
    bool atEnd() { ws(); return mP >= mEnd; }
    std::string error;

private:
    bool fail(const char* msg) {
        if (error.empty()) error = msg;
        return false;
    }
    bool lit(const char* s) {
        size_t n = std::strlen(s);
        if ((size_t)(mEnd - mP) < n || std::memcmp(mP, s, n) != 0) return false;
        mP += n;
        return true;
    }
    bool parseObject(JsonValue& out, int depth) {
        out.type = JsonValue::Type::Object;
        ++mP; // '{'
        ws();
        if (mP < mEnd && *mP == '}') { ++mP; return true; }
        while (true) {
            ws();
            if (mP >= mEnd || *mP != '"') return fail("expected key");
            std::string key;
            if (!parseString(key)) return false;
            ws();
            if (mP >= mEnd || *mP != ':') return fail("expected ':'");
            ++mP;
            JsonValue v;
            if (!parseValue(v, depth + 1)) return false;
            out.obj.emplace_back(std::move(key), std::move(v));
            ws();
            if (mP < mEnd && *mP == ',') { ++mP; continue; }
            if (mP < mEnd && *mP == '}') { ++mP; return true; }
            return fail("expected ',' or '}'");
        }
    }
    bool parseArray(JsonValue& out, int depth) {
        out.type = JsonValue::Type::Array;
        ++mP; // '['
        ws();
        if (mP < mEnd && *mP == ']') { ++mP; return true; }
        while (true) {
            JsonValue v;
            if (!parseValue(v, depth + 1)) return false;
            out.arr.push_back(std::move(v));
            ws();
            if (mP < mEnd && *mP == ',') { ++mP; continue; }
            if (mP < mEnd && *mP == ']') { ++mP; return true; }
            return fail("expected ',' or ']'");
        }
    }
    bool parseString(std::string& out) {
        ++mP; // '"'
        while (mP < mEnd) {
            unsigned char c = (unsigned char)*mP;
            if (c == '"') { ++mP; return true; }
            if (c == '\\') {
                ++mP;
                if (mP >= mEnd) return fail("bad escape");
                char e = *mP++;
                switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    unsigned cp;
                    if (!hex4(cp)) return fail("bad \\u escape");
                    if (cp >= 0xD800 && cp <= 0xDBFF) { // surrogate pair
                        if (mP + 1 < mEnd && mP[0] == '\\' && mP[1] == 'u') {
                            mP += 2;
                            unsigned lo;
                            if (!hex4(lo) || lo < 0xDC00 || lo > 0xDFFF)
                                return fail("bad surrogate");
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else {
                            cp = 0xFFFD;
                        }
                    }
                    appendUtf8(out, cp);
                    break;
                }
                default: return fail("bad escape");
                }
            } else {
                out += (char)c;
                ++mP;
            }
        }
        return fail("unterminated string");
    }
    bool hex4(unsigned& out) {
        if (mEnd - mP < 4) return false;
        out = 0;
        for (int i = 0; i < 4; ++i) {
            char c = *mP++;
            out <<= 4;
            if (c >= '0' && c <= '9') out |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') out |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') out |= (unsigned)(c - 'A' + 10);
            else return false;
        }
        return true;
    }
    static void appendUtf8(std::string& out, unsigned cp) {
        if (cp < 0x80) out += (char)cp;
        else if (cp < 0x800) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }
    bool parseNumber(JsonValue& out) {
        const char* start = mP;
        if (mP < mEnd && *mP == '-') ++mP;
        while (mP < mEnd && ((*mP >= '0' && *mP <= '9') || *mP == '.' || *mP == 'e' ||
                             *mP == 'E' || *mP == '+' || *mP == '-'))
            ++mP;
        if (mP == start) return fail("bad number");
        std::string num(start, (size_t)(mP - start));
        char* end = nullptr;
        out.number = std::strtod(num.c_str(), &end);
        if (!end || *end != '\0') return fail("bad number");
        out.type = JsonValue::Type::Number;
        return true;
    }

    const char* mP;
    const char* mEnd;
};

} // namespace

JsonValue JsonValue::parse(const std::string& text, std::string* err) {
    JsonValue out;
    if (text.size() > 1024 * 1024) {
        if (err) *err = "JSON body too large";
        return out;
    }
    Parser p(text.data(), text.data() + text.size());
    if (!p.parseValue(out, 0) || !p.atEnd()) {
        if (err) *err = p.error.empty() ? "trailing data" : p.error;
        out = JsonValue{};
    }
    return out;
}

} // namespace avb
