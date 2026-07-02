/*
 * SPDX-FileCopyrightText: 2025 Kebag-Logic (https://kebag-logic.com)
 * SPDX-FileCopyrightText: 2025 Alexandre Malki <alexandre.malki@kebag-logic.com>
 * SPDX-License-Identifier: MIT
 *
 * Vendored unmodified from TSN-GEN (parser/inc/logic_module.h) — the stable
 * logic-override contract (BE-2). Protocol state machines in this backend
 * implement this interface so they can be linked into TSN-GEN unchanged
 * once its Stack runtime serializer lands.
 */
#pragma once

#include <string>

class LayerContext;

/**
 * @brief Pluggable per-layer logic hook invoked by the Stack runtime.
 *
 *  A module may fill derived fields before serialization (onEncode),
 *  validate / update state after parsing (onDecode), or steer demux
 *  on the receive path (nextLayer). All methods are optional — the
 *  default implementations are no-ops, which is exactly what
 *  PassthroughLogic relies on.
 */
class ILogicModule {
public:
    virtual ~ILogicModule() = default;

    virtual void onEncode(LayerContext& /*ctx*/) {}
    virtual void onDecode(LayerContext& /*ctx*/) {}

    /**
     * @brief Demux hook. Return the service name of the upper layer
     *        to dispatch to on decode, or "" when the next layer is
     *        fixed by the stack definition.
     */
    virtual std::string nextLayer(const LayerContext& /*ctx*/) const
    {
        return {};
    }
};

/**
 * @brief Default module used when a layer declares no logic or is
 *        explicitly bypassed (bypass-logic: true) in the stack YAML.
 */
class PassthroughLogic final : public ILogicModule {};
