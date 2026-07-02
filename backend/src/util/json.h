/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Minimal JSON writer/parser — enough for the REST API, no external deps.
 */
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace avb {

/** Streaming JSON writer with automatic comma placement. */
class JsonWriter {
public:
    JsonWriter& beginObj() { comma(); mOut += '{'; push(); return *this; }
    JsonWriter& endObj() { mOut += '}'; pop(); return *this; }
    JsonWriter& beginArr() { comma(); mOut += '['; push(); return *this; }
    JsonWriter& endArr() { mOut += ']'; pop(); return *this; }

    JsonWriter& key(const std::string& k) {
        comma();
        appendEscaped(k);
        mOut += ':';
        mPendingKey = true;
        return *this;
    }
    JsonWriter& value(const std::string& v) { comma(); appendEscaped(v); return *this; }
    JsonWriter& value(const char* v) { return value(std::string(v)); }
    JsonWriter& value(bool v) { comma(); mOut += v ? "true" : "false"; return *this; }
    JsonWriter& value(int64_t v) { comma(); mOut += std::to_string(v); return *this; }
    JsonWriter& value(uint64_t v) { comma(); mOut += std::to_string(v); return *this; }
    JsonWriter& value(int v) { return value((int64_t)v); }
    JsonWriter& value(unsigned v) { return value((uint64_t)v); }
    JsonWriter& value(double v);
    JsonWriter& null() { comma(); mOut += "null"; return *this; }
    /** Insert pre-serialized JSON verbatim. */
    JsonWriter& raw(const std::string& json) { comma(); mOut += json; return *this; }

    JsonWriter& kv(const std::string& k, const std::string& v) { return key(k).value(v); }
    JsonWriter& kv(const std::string& k, const char* v) { return key(k).value(v); }
    JsonWriter& kv(const std::string& k, bool v) { return key(k).value(v); }
    JsonWriter& kv(const std::string& k, int64_t v) { return key(k).value(v); }
    JsonWriter& kv(const std::string& k, uint64_t v) { return key(k).value(v); }
    JsonWriter& kv(const std::string& k, int v) { return key(k).value(v); }
    JsonWriter& kv(const std::string& k, unsigned v) { return key(k).value(v); }
    JsonWriter& kv(const std::string& k, double v) { return key(k).value(v); }

    const std::string& str() const { return mOut; }
    std::string take() { return std::move(mOut); }

private:
    void comma() {
        if (mPendingKey) { mPendingKey = false; return; }
        if (!mNeedComma.empty() && mNeedComma.back()) mOut += ',';
        if (!mNeedComma.empty()) mNeedComma.back() = true;
    }
    void push() { mNeedComma.push_back(false); }
    void pop() {
        if (!mNeedComma.empty()) mNeedComma.pop_back();
        if (!mNeedComma.empty()) mNeedComma.back() = true;
    }
    void appendEscaped(const std::string& s);

    std::string mOut;
    std::vector<bool> mNeedComma;
    bool mPendingKey = false;
};

std::string jsonEscape(const std::string& s);

/** Parsed JSON value tree. */
class JsonValue {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    double number = 0;
    std::string str;
    std::vector<JsonValue> arr;
    std::vector<std::pair<std::string, JsonValue>> obj;

    bool isNull() const { return type == Type::Null; }
    bool isStr() const { return type == Type::String; }
    bool isNum() const { return type == Type::Number; }
    bool isObj() const { return type == Type::Object; }

    /** Object member lookup; returns nullptr when absent or not an object. */
    const JsonValue* get(const std::string& k) const {
        if (type != Type::Object) return nullptr;
        for (auto& [key, v] : obj)
            if (key == k) return &v;
        return nullptr;
    }
    std::string getStr(const std::string& k, const std::string& dflt = "") const {
        auto* v = get(k);
        return (v && v->type == Type::String) ? v->str : dflt;
    }
    double getNum(const std::string& k, double dflt = 0) const {
        auto* v = get(k);
        return (v && v->type == Type::Number) ? v->number : dflt;
    }

    /** Parse; on failure returns Null and sets *err. Input capped at 1 MiB. */
    static JsonValue parse(const std::string& text, std::string* err = nullptr);
};

} // namespace avb
