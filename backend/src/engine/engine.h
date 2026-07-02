/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Analysis engine: parallel decode of the capture partitioned across CPU
 * cores (CO-2), strict capture-timestamp re-ordering before the
 * single-threaded state pass (CO-3), events appended live for streaming
 * clients.
 */
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "session.h"

namespace avb {

class Engine {
public:
    /** Register a session and start its analysis on a background thread. */
    void start(std::shared_ptr<Session> session);

    std::shared_ptr<Session> find(const std::string& id) const;
    std::vector<std::shared_ptr<Session>> list() const;
    bool remove(const std::string& id);
    void add(std::shared_ptr<Session> session); // without starting (restore)

    /** Blocks until every running analysis finished (shutdown/testing). */
    void drain();

private:
    void analyze(std::shared_ptr<Session> s);

    mutable std::mutex mMu;
    std::map<std::string, std::shared_ptr<Session>> mSessions;
    std::condition_variable mDrainCv;
    unsigned mRunning = 0;
};

} // namespace avb
