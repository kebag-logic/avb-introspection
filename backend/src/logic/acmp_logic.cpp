/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * ACMP connection state per (talker, talker_unique, listener,
 * listener_unique) stream pair (IEEE 1722.1 / Milan v1.2), with
 * command/response correlation and the standard's per-command timeouts.
 */
#include <map>
#include <tuple>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

// IEEE 1722.1 ACMP command timeouts, ms, indexed by command message type.
double acmpTimeoutS(uint8_t cmdMsgType) {
    switch (cmdMsgType) {
    case 0: return 2.000;  // CONNECT_TX
    case 2: return 0.200;  // DISCONNECT_TX
    case 4: return 0.200;  // GET_TX_STATE
    case 6: return 4.500;  // CONNECT_RX
    case 8: return 0.500;  // DISCONNECT_RX
    case 10: return 0.200; // GET_RX_STATE
    case 12: return 0.200; // GET_TX_CONNECTION
    }
    return 1.0;
}

class AcmpLogic final : public AvbLogicBase {
public:
    void onDecode(LayerContext& ctx) override {
        auto* v = dynamic_cast<VarLayerContext*>(&ctx);
        if (!v) return;
        double ts = tsOf(*v);
        uint32_t n = numOf(*v);
        uint8_t msg = (uint8_t)v->at("message_type");
        uint8_t status = (uint8_t)v->at("status");

        ConnKey key{v->at("talker_entity_id"), (uint16_t)v->at("talker_unique_id"),
                    v->at("listener_entity_id"),
                    (uint16_t)v->at("listener_unique_id")};
        auto& c = mConns[key];
        c.key = key;
        if (c.state.empty()) c.state = "DISCONNECTED";
        c.controller = v->at("controller_entity_id");

        bool isCommand = (msg % 2) == 0;
        if (isCommand) {
            mInflight[{msg, (uint16_t)v->at("sequence_id"), key}] = {ts, n};
        } else {
            mInflight.erase({(uint8_t)(msg - 1), (uint16_t)v->at("sequence_id"), key});
        }

        switch (msg) {
        case 0: // CONNECT_TX_COMMAND
        case 6: // CONNECT_RX_COMMAND
            if (c.state != "CONNECTING" && c.state != "CONNECTED")
                transition(c, ts, n, "CONNECTING",
                           acmpMsgName(msg) + " from controller " +
                               idStr(c.controller));
            break;
        case 1: // CONNECT_TX_RESPONSE — talker allocated the stream
            if (status == 0) {
                c.streamId = v->at("stream_id");
                c.destMac = v->at("stream_dest_mac");
                c.vlan = (uint16_t)v->at("stream_vlan_id");
                if (c.state != "CONNECTED" && c.state != "CONNECTING")
                    transition(c, ts, n, "CONNECTING",
                               "CONNECT_TX_RESPONSE (fast connect?)");
            } else {
                transition(c, ts, n, "FAILED",
                           "CONNECT_TX_RESPONSE " + acmpStatusName(status));
            }
            break;
        case 7: // CONNECT_RX_RESPONSE — listener confirmed
            if (status == 0) {
                c.streamId = v->at("stream_id");
                c.destMac = v->at("stream_dest_mac");
                c.vlan = (uint16_t)v->at("stream_vlan_id");
                c.connCount = (uint16_t)v->at("connection_count");
                transition(c, ts, n, "CONNECTED", "CONNECT_RX_RESPONSE SUCCESS");
            } else {
                transition(c, ts, n, "FAILED",
                           "CONNECT_RX_RESPONSE " + acmpStatusName(status));
            }
            break;
        case 2: // DISCONNECT_TX_COMMAND
        case 8: // DISCONNECT_RX_COMMAND
            if (c.state != "DISCONNECTED")
                transition(c, ts, n, "DISCONNECTING", acmpMsgName(msg));
            break;
        case 3: // DISCONNECT_TX_RESPONSE
        case 9: // DISCONNECT_RX_RESPONSE
            if (status == 0) {
                if (c.state != "DISCONNECTED") {
                    if (msg == 9)
                        c.connCount = (uint16_t)v->at("connection_count");
                    transition(c, ts, n, "DISCONNECTED",
                               acmpMsgName(msg) + " SUCCESS");
                }
            } else if (c.state == "DISCONNECTING") {
                transition(c, ts, n, "CONNECTED",
                           acmpMsgName(msg) + " " + acmpStatusName(status) +
                               " — disconnect rejected");
            }
            break;
        default: // GET_*_STATE / GET_TX_CONNECTION — observational only
            break;
        }
    }

    void onTimeTick(double ts) override {
        for (auto it = mInflight.begin(); it != mInflight.end();) {
            auto [cmdMsg, seq, key] = it->first;
            if (ts <= it->second.sentTs + acmpTimeoutS(cmdMsg)) {
                ++it;
                continue;
            }
            auto& c = mConns[key];
            std::string cmd = acmpMsgName(cmdMsg);
            if (cmdMsg == 0 || cmdMsg == 6) {
                if (c.state == "CONNECTING")
                    transition(c, ts, 0, "FAILED", cmd + " timed out");
            } else if (cmdMsg == 2 || cmdMsg == 8) {
                if (c.state == "DISCONNECTING")
                    transition(c, ts, 0, "DISCONNECTED",
                               cmd + " timed out (assumed disconnected)");
            }
            it = mInflight.erase(it);
        }
    }

    void snapshot(JsonWriter& w) const override {
        w.key("connections").beginArr();
        for (auto& [key, c] : mConns) {
            w.beginObj();
            w.kv("talker_entity", idStr(key.talker));
            w.kv("talker_unique_id", (uint64_t)key.talkerUid);
            w.kv("listener_entity", idStr(key.listener));
            w.kv("listener_unique_id", (uint64_t)key.listenerUid);
            w.kv("controller_entity", idStr(c.controller));
            w.kv("stream_id", idStr(c.streamId));
            w.kv("dest_mac", c.destMac ? macStr(c.destMac) : "");
            w.kv("vlan", (uint64_t)c.vlan);
            w.kv("connection_count", (uint64_t)c.connCount);
            w.kv("state", c.state);
            histJson(w, c.hist);
            w.endObj();
        }
        w.endArr();
    }

private:
    struct ConnKey {
        uint64_t talker = 0;
        uint16_t talkerUid = 0;
        uint64_t listener = 0;
        uint16_t listenerUid = 0;
        bool operator<(const ConnKey& o) const {
            return std::tie(talker, talkerUid, listener, listenerUid) <
                   std::tie(o.talker, o.talkerUid, o.listener, o.listenerUid);
        }
    };
    struct Conn {
        ConnKey key;
        uint64_t controller = 0, streamId = 0, destMac = 0;
        uint16_t vlan = 0, connCount = 0;
        std::string state;
        std::vector<HistEntry> hist;
    };
    struct Inflight {
        double sentTs = 0;
        uint32_t n = 0;
    };

    std::string connName(const ConnKey& k) const {
        return idStr(k.talker) + "[" + std::to_string(k.talkerUid) + "] -> " +
               idStr(k.listener) + "[" + std::to_string(k.listenerUid) + "]";
    }

    void transition(Conn& c, double ts, uint32_t n, const std::string& to,
                    const std::string& why) {
        std::string from = c.state.empty() ? "DISCONNECTED" : c.state;
        if (from == to) return;
        c.state = to;
        c.hist.push_back({ts, n, from, to, why});
        Transition t;
        t.proto = Proto::ACMP;
        t.object = "connection " + connName(c.key);
        t.from = from;
        t.to = to;
        t.why = why;
        t.entity = idStr(c.key.listener);
        t.stream = c.streamId ? idStr(c.streamId) : "";
        std::string tn = mShared ? mShared->nameOf(c.key.talker) : "";
        std::string ln = mShared ? mShared->nameOf(c.key.listener) : "";
        t.summary = "Connection " + (tn.empty() ? idStr(c.key.talker) : tn) + "[" +
                    std::to_string(c.key.talkerUid) + "] -> " +
                    (ln.empty() ? idStr(c.key.listener) : ln) + "[" +
                    std::to_string(c.key.listenerUid) + "]: " + from + " -> " + to +
                    " — " + why;
        emit(std::move(t));
    }

    std::map<std::tuple<uint8_t, uint16_t, ConnKey>, Inflight> mInflight;
    std::map<ConnKey, Conn> mConns;
};

REGISTER_LOGIC("atdecc_acmp", AcmpLogic)

} // namespace
} // namespace avb
