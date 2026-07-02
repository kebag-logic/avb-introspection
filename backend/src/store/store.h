/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * On-disk persistence (BE-8): uploaded pcaps and session metadata live
 * under the data directory and survive backend restarts. Layout:
 *   <data>/users.json          (owned by Auth)
 *   <data>/meta.json           (pcap + session metadata, id counters)
 *   <data>/pcaps/<id>.pcap     (uploaded captures)
 */
#pragma once

#include <mutex>
#include <string>
#include <vector>

namespace avb {

class Store {
public:
    struct PcapMeta {
        std::string id, name, uploadedAt;
        uint64_t size = 0;
    };
    struct SessionMeta {
        std::string id, name, pcapId, path, createdAt;
    };

    bool init(const std::string& dataDir, std::string& err);

    const std::string& dataDir() const { return mDataDir; }
    std::string usersFile() const { return mDataDir + "/users.json"; }

    /** Persist an uploaded pcap; returns its id ("" on error). */
    std::string addPcap(const std::string& name, const std::string& bytes,
                        std::string& err);
    std::vector<PcapMeta> pcaps() const;
    bool hasPcap(const std::string& id) const;
    std::string pcapPath(const std::string& id) const;
    std::string pcapName(const std::string& id) const;

    /** Persist session metadata; assigns and returns the session id. */
    std::string addSession(SessionMeta meta);
    void removeSession(const std::string& id);
    std::vector<SessionMeta> sessions() const;

    static std::string nowIso8601();

private:
    bool save(std::string& err);

    std::string mDataDir;
    mutable std::mutex mMu;
    uint64_t mNextPcap = 1, mNextSession = 1;
    std::vector<PcapMeta> mPcaps;
    std::vector<SessionMeta> mSessions;
};

} // namespace avb
