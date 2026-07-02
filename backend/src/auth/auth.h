/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * User accounts (SE-1..SE-3): registration with Argon2id password hashes
 * (libsodium crypto_pwhash_str), opaque random bearer tokens for sessions.
 */
#pragma once

#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

namespace avb {

class Auth {
public:
    /** Loads users from `usersFile` (created on first save). */
    bool init(const std::string& usersFile, std::string& err);

    bool registerUser(const std::string& username, const std::string& password,
                      std::string& err);
    /** On success fills `token` (64 hex chars). */
    bool login(const std::string& username, const std::string& password,
               std::string& token);
    /** Token -> username; empty when invalid. */
    std::string check(const std::string& token) const;
    void logout(const std::string& token);

    static bool validUsername(const std::string& u);

private:
    bool save(std::string& err);

    std::string mPath;
    mutable std::mutex mMu;
    std::map<std::string, std::string> mUsers;              // name -> pw hash
    std::unordered_map<std::string, std::string> mTokens;   // token -> name
};

} // namespace avb
