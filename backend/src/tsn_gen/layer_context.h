/*
 * SPDX-FileCopyrightText: 2025 Kebag-Logic (https://kebag-logic.com)
 * SPDX-FileCopyrightText: 2025 Alexandre Malki <alexandre.malki@kebag-logic.com>
 * SPDX-License-Identifier: MIT
 *
 * Vendored unmodified from TSN-GEN (parser/inc/layer_context.h).
 * See var_context.h for this backend's concrete subclass whose accessors
 * are backed by real decoded fields (TSN-GEN v1 ships them as stubs).
 */
#pragma once

#include <cstdint>
#include <string>
#include <utility>

/**
 * @brief Runtime context handed to an ILogicModule on encode/decode.
 */
class LayerContext {
public:
    LayerContext() = default;
    explicit LayerContext(std::string serviceName)
        : mServiceName(std::move(serviceName)) {}
    virtual ~LayerContext() = default;

    const std::string& getServiceName() const { return mServiceName; }

    LayerContext* upper() const { return mUpper; }
    LayerContext* lower() const { return mLower; }
    void setUpper(LayerContext* u) { mUpper = u; }
    void setLower(LayerContext* l) { mLower = l; }

    /**
     * @brief Read a var value from this layer by its short (unqualified) name.
     * @return true on success; false if the name is unknown at this layer.
     */
    virtual bool getValue(const std::string& /*name*/, uint64_t& /*out*/) const
    {
        return false;
    }

    /**
     * @brief Write a var value on this layer by its short name.
     * @return true on success; false if the name is unknown or read-only.
     */
    virtual bool setValue(const std::string& /*name*/, uint64_t /*value*/)
    {
        return false;
    }

private:
    std::string mServiceName;
    LayerContext* mUpper = nullptr;
    LayerContext* mLower = nullptr;
};
