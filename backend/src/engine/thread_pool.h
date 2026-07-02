/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Demand-grown thread pool (CO-1): serving threads are added while work is
 * queued and no worker is idle, up to a configurable maximum.
 */
#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace avb {

class ThreadPool {
public:
    explicit ThreadPool(unsigned maxThreads)
        : mMax(maxThreads ? maxThreads : 1) {}

    ~ThreadPool() { stop(); }

    void post(std::function<void()> fn) {
        {
            std::lock_guard lk(mMu);
            if (mStopping) return;
            mQueue.push_back(std::move(fn));
            if (mIdle == 0 && mThreads.size() < mMax)
                mThreads.emplace_back([this] { worker(); });
        }
        mCv.notify_one();
    }

    void stop() {
        {
            std::lock_guard lk(mMu);
            if (mStopping) return;
            mStopping = true;
        }
        mCv.notify_all();
        for (auto& t : mThreads)
            if (t.joinable()) t.join();
        mThreads.clear();
    }

    unsigned threadCount() const {
        std::lock_guard lk(mMu);
        return (unsigned)mThreads.size();
    }
    unsigned maxThreads() const { return mMax; }
    unsigned active() const { return mActive.load(); }
    unsigned queued() const {
        std::lock_guard lk(mMu);
        return (unsigned)mQueue.size();
    }

private:
    void worker() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock lk(mMu);
                ++mIdle;
                mCv.wait(lk, [this] { return mStopping || !mQueue.empty(); });
                --mIdle;
                if (mStopping && mQueue.empty()) return;
                task = std::move(mQueue.front());
                mQueue.pop_front();
            }
            ++mActive;
            task();
            --mActive;
        }
    }

    mutable std::mutex mMu;
    std::condition_variable mCv;
    std::deque<std::function<void()>> mQueue;
    std::vector<std::thread> mThreads;
    unsigned mMax;
    unsigned mIdle = 0;
    std::atomic<unsigned> mActive{0};
    bool mStopping = false;
};

} // namespace avb
