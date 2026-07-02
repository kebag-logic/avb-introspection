/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Registry implementation matching the vendored TSN-GEN contract.
 */
#include "logic_registry.h"

LogicRegistry& LogicRegistry::instance() {
    static LogicRegistry reg;
    return reg;
}

bool LogicRegistry::add(const std::string& name, Factory factory) {
    if (name.empty() || !factory) return false;
    auto [it, inserted] = mFactories.emplace(name, std::move(factory));
    (void)it;
    return inserted;
}

std::unique_ptr<ILogicModule> LogicRegistry::create(const std::string& name) const {
    auto it = mFactories.find(name);
    return it == mFactories.end() ? nullptr : it->second();
}

bool LogicRegistry::has(const std::string& name) const {
    return mFactories.count(name) != 0;
}

size_t LogicRegistry::size() const { return mFactories.size(); }
