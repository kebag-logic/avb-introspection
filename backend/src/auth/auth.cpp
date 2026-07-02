/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "auth.h"

#include <sodium.h>

#include <fstream>
#include <sstream>

#include "../util/json.h"

namespace avb {

bool Auth::validUsername(const std::string& u) {
    if (u.size() < 3 || u.size() > 32) return false;
    for (char c : u) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool Auth::init(const std::string& usersFile, std::string& err) {
    if (sodium_init() < 0) {
        err = "libsodium initialization failed";
        return false;
    }
    mPath = usersFile;

    std::ifstream f(usersFile);
    if (!f) return true; // first run — file created on first register
    std::stringstream ss;
    ss << f.rdbuf();
    std::string perr;
    JsonValue root = JsonValue::parse(ss.str(), &perr);
    if (root.isNull()) {
        err = "cannot parse " + usersFile + ": " + perr;
        return false;
    }
    if (auto* users = root.get("users"); users) {
        for (auto& u : users->arr) {
            std::string name = u.getStr("username");
            std::string hash = u.getStr("hash");
            if (!name.empty() && !hash.empty()) mUsers[name] = hash;
        }
    }
    return true;
}

bool Auth::save(std::string& err) {
    JsonWriter w;
    w.beginObj().key("users").beginArr();
    for (auto& [name, hash] : mUsers) {
        w.beginObj();
        w.kv("username", name);
        w.kv("hash", hash);
        w.endObj();
    }
    w.endArr().endObj();

    std::string tmp = mPath + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            err = "cannot write " + tmp;
            return false;
        }
        f << w.str();
    }
    if (std::rename(tmp.c_str(), mPath.c_str()) != 0) {
        err = "cannot replace " + mPath;
        return false;
    }
    return true;
}

bool Auth::registerUser(const std::string& username,
                        const std::string& password, std::string& err) {
    if (!validUsername(username)) {
        err = "username must be 3-32 chars of [a-zA-Z0-9_.-]";
        return false;
    }
    if (password.size() < 8) {
        err = "password must be at least 8 characters";
        return false;
    }
    std::lock_guard lk(mMu);
    if (mUsers.count(username)) {
        err = "username already exists";
        return false;
    }
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password.c_str(), password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        err = "hashing failed (out of memory?)";
        return false;
    }
    mUsers[username] = hash;
    return save(err);
}

bool Auth::login(const std::string& username, const std::string& password,
                 std::string& token) {
    std::lock_guard lk(mMu);
    auto it = mUsers.find(username);
    if (it == mUsers.end()) return false;
    if (crypto_pwhash_str_verify(it->second.c_str(), password.c_str(),
                                 password.size()) != 0)
        return false;

    unsigned char raw[32];
    randombytes_buf(raw, sizeof raw);
    char hex[65];
    sodium_bin2hex(hex, sizeof hex, raw, sizeof raw);
    token = hex;
    mTokens[token] = username;
    return true;
}

std::string Auth::check(const std::string& token) const {
    if (token.empty()) return {};
    std::lock_guard lk(mMu);
    auto it = mTokens.find(token);
    return it == mTokens.end() ? std::string() : it->second;
}

void Auth::logout(const std::string& token) {
    std::lock_guard lk(mMu);
    mTokens.erase(token);
}

} // namespace avb
