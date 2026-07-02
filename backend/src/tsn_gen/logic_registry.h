/*
 * SPDX-FileCopyrightText: 2025 Kebag-Logic (https://kebag-logic.com)
 * SPDX-FileCopyrightText: 2025 Alexandre Malki <alexandre.malki@kebag-logic.com>
 * SPDX-License-Identifier: MIT
 *
 * Vendored unmodified from TSN-GEN (parser/inc/logic_registry.h).
 */
#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "logic_module.h"

/**
 * @brief Process-wide string -> ILogicModule factory.
 *
 *  Logic modules register themselves at static init via REGISTER_LOGIC.
 */
class LogicRegistry {
public:
    using Factory = std::function<std::unique_ptr<ILogicModule>()>;

    static LogicRegistry& instance();

    bool add(const std::string& name, Factory factory);
    std::unique_ptr<ILogicModule> create(const std::string& name) const;
    bool has(const std::string& name) const;
    size_t size() const;

private:
    LogicRegistry() = default;
    LogicRegistry(const LogicRegistry&) = delete;
    LogicRegistry& operator=(const LogicRegistry&) = delete;

    std::unordered_map<std::string, Factory> mFactories;
};

#define REGISTER_LOGIC(NAME, CLASS)                                         \
    namespace {                                                             \
        const bool _logic_reg_##CLASS =                                     \
            ::LogicRegistry::instance().add(                                \
                (NAME), [] { return std::make_unique<CLASS>(); });          \
    }
