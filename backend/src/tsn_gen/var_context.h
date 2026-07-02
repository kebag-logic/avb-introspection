/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Concrete LayerContext whose var accessors are backed by decoded fields.
 * TSN-GEN v1 ships getValue/setValue as stubs pending its Stack serializer;
 * this subclass is the working stand-in so logic modules run for real here.
 *
 * getBytes/setBytes anticipate TSN-GEN's planned typed accessors (its docs:
 * "typed accessors will be added") for fields that do not fit uint64_t,
 * e.g. the 64-byte AEM entity_name. Modules reach them via dynamic_cast —
 * the introspection pattern TSN-GEN documents.
 */
#pragma once

#include <string>
#include <unordered_map>

#include "layer_context.h"

namespace avb {

class VarLayerContext final : public LayerContext {
public:
    VarLayerContext() = default;
    explicit VarLayerContext(std::string serviceName)
        : LayerContext(std::move(serviceName)) {}

    bool getValue(const std::string& name, uint64_t& out) const override {
        auto it = mVars.find(name);
        if (it == mVars.end()) return false;
        out = it->second;
        return true;
    }

    bool setValue(const std::string& name, uint64_t value) override {
        mVars[name] = value;
        return true;
    }

    bool getBytes(const std::string& name, std::string& out) const {
        auto it = mBytes.find(name);
        if (it == mBytes.end()) return false;
        out = it->second;
        return true;
    }

    void setBytes(const std::string& name, std::string value) {
        mBytes[name] = std::move(value);
    }

    /** Convenience for module code: value or 0 when the var is absent. */
    uint64_t at(const std::string& name) const {
        uint64_t v = 0;
        getValue(name, v);
        return v;
    }

private:
    std::unordered_map<std::string, uint64_t> mVars;
    std::unordered_map<std::string, std::string> mBytes;
};

} // namespace avb
