/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "store.h"

#include <sys/stat.h>

#include <cstdio>
#include <ctime>
#include <fstream>
#include <sstream>

#include "../util/json.h"

namespace avb {

std::string Store::nowIso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

bool Store::init(const std::string& dataDir, std::string& err) {
    mDataDir = dataDir;
    if (::mkdir(dataDir.c_str(), 0755) != 0 && errno != EEXIST) {
        err = "cannot create data directory " + dataDir;
        return false;
    }
    std::string pcapDir = dataDir + "/pcaps";
    if (::mkdir(pcapDir.c_str(), 0755) != 0 && errno != EEXIST) {
        err = "cannot create " + pcapDir;
        return false;
    }

    std::ifstream f(dataDir + "/meta.json");
    if (!f) return true; // fresh data dir
    std::stringstream ss;
    ss << f.rdbuf();
    std::string perr;
    JsonValue root = JsonValue::parse(ss.str(), &perr);
    if (root.isNull()) {
        err = "cannot parse meta.json: " + perr;
        return false;
    }
    mNextPcap = (uint64_t)root.getNum("next_pcap", 1);
    mNextSession = (uint64_t)root.getNum("next_session", 1);
    if (auto* arr = root.get("pcaps"); arr)
        for (auto& p : arr->arr)
            mPcaps.push_back({p.getStr("id"), p.getStr("name"),
                              p.getStr("uploaded_at"),
                              (uint64_t)p.getNum("size")});
    if (auto* arr = root.get("sessions"); arr)
        for (auto& s : arr->arr)
            mSessions.push_back({s.getStr("id"), s.getStr("name"),
                                 s.getStr("pcap_id"), s.getStr("path"),
                                 s.getStr("created_at")});
    return true;
}

bool Store::save(std::string& err) {
    JsonWriter w;
    w.beginObj();
    w.kv("next_pcap", mNextPcap);
    w.kv("next_session", mNextSession);
    w.key("pcaps").beginArr();
    for (auto& p : mPcaps) {
        w.beginObj();
        w.kv("id", p.id);
        w.kv("name", p.name);
        w.kv("uploaded_at", p.uploadedAt);
        w.kv("size", p.size);
        w.endObj();
    }
    w.endArr();
    w.key("sessions").beginArr();
    for (auto& s : mSessions) {
        w.beginObj();
        w.kv("id", s.id);
        w.kv("name", s.name);
        w.kv("pcap_id", s.pcapId);
        w.kv("path", s.path);
        w.kv("created_at", s.createdAt);
        w.endObj();
    }
    w.endArr();
    w.endObj();

    std::string path = mDataDir + "/meta.json";
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            err = "cannot write " + tmp;
            return false;
        }
        f << w.str();
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        err = "cannot replace " + path;
        return false;
    }
    return true;
}

std::string Store::addPcap(const std::string& name, const std::string& bytes,
                           std::string& err) {
    std::lock_guard lk(mMu);
    std::string id = "p" + std::to_string(mNextPcap);
    std::string path = mDataDir + "/pcaps/" + id + ".pcap";
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) {
            err = "cannot write " + path;
            return "";
        }
        f.write(bytes.data(), (std::streamsize)bytes.size());
        if (!f) {
            err = "short write to " + path + " (disk full?)";
            return "";
        }
    }
    mNextPcap++;
    mPcaps.push_back({id, name, nowIso8601(), bytes.size()});
    if (!save(err)) {
        std::remove(path.c_str());
        mPcaps.pop_back();
        return "";
    }
    return id;
}

std::vector<Store::PcapMeta> Store::pcaps() const {
    std::lock_guard lk(mMu);
    return mPcaps;
}

bool Store::hasPcap(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps)
        if (p.id == id) return true;
    return false;
}

std::string Store::pcapPath(const std::string& id) const {
    return mDataDir + "/pcaps/" + id + ".pcap";
}

std::string Store::pcapName(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps)
        if (p.id == id) return p.name;
    return {};
}

std::string Store::addSession(SessionMeta meta) {
    std::lock_guard lk(mMu);
    meta.id = "s" + std::to_string(mNextSession++);
    meta.createdAt = nowIso8601();
    mSessions.push_back(meta);
    std::string err;
    save(err); // metadata loss on failure is non-fatal; sessions still run
    return meta.id;
}

void Store::removeSession(const std::string& id) {
    std::lock_guard lk(mMu);
    std::erase_if(mSessions, [&](const SessionMeta& s) { return s.id == id; });
    std::string err;
    save(err);
}

std::vector<Store::SessionMeta> Store::sessions() const {
    std::lock_guard lk(mMu);
    return mSessions;
}

} // namespace avb
