/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * ACMP connection state per (talker, talker_unique, listener,
 * listener_unique) stream pair (IEEE 1722.1), with command/response
 * correlation — plus the Milan v1.2 connection model (§5.5):
 *
 *  - Listener sink state machine (§5.5.3): UNBOUND, PRB_W_AVAIL,
 *    PRB_W_DELAY, PRB_W_RESP, PRB_W_RESP2, PRB_W_RETRY, SETTLED_NO_RSV,
 *    SETTLED_RSV_OK — reconstructed from the wire (BIND/UNBIND/PROBE
 *    messages; Milan renames CONNECT_RX→BIND_RX, DISCONNECT_RX→UNBIND_RX,
 *    CONNECT_TX→PROBE_TX over the same wire values) and from cross-protocol
 *    truth in SharedModel (ADP availability = EVT_TK_DISCOVERED/DEPARTED,
 *    MSRP talker attributes = EVT_TK_REGISTERED/UNREGISTERED).
 *  - Talker source record (§5.5.2.7/§5.5.4): Milan talkers keep NO
 *    per-listener connection state — they answer PROBE_TX queries and rely
 *    on SRP alone, so the observer records behavior, not a state machine.
 */
#include <map>
#include <tuple>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

// Milan v1.2 Table 5.26 command timeouts (all 200 ms — the profile replaces
// the larger IEEE 1722.1 Table 8-1 values).
double acmpTimeoutS(uint8_t cmdMsgType) {
    (void)cmdMsgType;
    return 0.200;
}

// Milan §5.5.3.3 listener sink timers.
constexpr double kMilanNoRespS = 0.200; // TMR_NO_RESP
constexpr double kMilanRetryS = 4.0;    // TMR_RETRY
constexpr double kMilanNoTkS = 10.0;    // TMR_NO_TK

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

        milanOnMessage(*v, ts, n, msg, status);

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
        milanTick(ts);
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

        // Milan v1.2 §5.5.3 listener sink state machines.
        w.key("milan_sinks").beginArr();
        for (auto& [key, s] : mSinks) {
            w.beginObj();
            w.kv("listener_entity", idStr(s.listener));
            w.kv("listener_unique_id", (uint64_t)s.uid);
            w.kv("state", s.state.empty() ? "UNBOUND" : s.state);
            w.kv("probing_status", probingStatus(s.state));
            w.kv("bound_talker", s.boundTalker ? idStr(s.boundTalker) : "");
            w.kv("bound_talker_unique_id", (uint64_t)s.boundTalkerUid);
            w.kv("controller", s.controller ? idStr(s.controller) : "");
            w.kv("stream_id", s.streamId ? idStr(s.streamId) : "");
            w.kv("dest_mac", s.destMac ? macStr(s.destMac) : "");
            w.kv("vlan", (uint64_t)s.vlan);
            w.kv("probes_sent", (uint64_t)s.probes);
            histJson(w, s.hist);
            w.endObj();
        }
        w.endArr();

        // Milan v1.2 §5.5.2.7 talkers are stateless: observed behavior only.
        w.key("milan_talkers").beginArr();
        for (auto& [key, t] : mTalkers) {
            w.beginObj();
            w.kv("talker_entity", idStr(t.talker));
            w.kv("talker_unique_id", (uint64_t)t.uid);
            w.kv("probes_received", (uint64_t)t.probesReceived);
            w.kv("probe_responses", (uint64_t)t.probeResponses);
            w.kv("last_status", acmpStatusName(t.lastStatus));
            w.kv("stream_id", t.streamId ? idStr(t.streamId) : "");
            w.kv("srp_declaration",
                 !mShared ? "NONE"
                 : !t.streamId ? "NONE"
                 : mShared->msrpTalkerDecl.count(t.streamId) == 0 ? "NONE"
                 : mShared->msrpTalkerDecl.at(t.streamId) == 1 ? "ADVERTISE"
                                                               : "FAILED");
            w.kv("disconnect_tx_seen", (uint64_t)t.disconnectTx);
            w.kv("get_tx_connection_seen", (uint64_t)t.getTxConnection);
            histJson(w, t.hist);
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

    // ---- Milan v1.2 §5.5: listener sink state machine + talker record ----

    struct MilanSink {
        uint64_t listener = 0;
        uint16_t uid = 0;
        std::string state; // "" -> UNBOUND
        uint64_t boundTalker = 0, controller = 0;
        uint16_t boundTalkerUid = 0;
        uint64_t streamId = 0, destMac = 0;
        uint16_t vlan = 0;
        uint32_t probes = 0;
        double lastProbeTs = -1, retryStartTs = -1, settledNoRsvTs = -1;
        bool talkerAvail = false, retryWarned = false;
        std::vector<HistEntry> hist;
    };
    struct MilanTalker {
        uint64_t talker = 0;
        uint16_t uid = 0;
        uint32_t probesReceived = 0, probeResponses = 0, disconnectTx = 0,
                 getTxConnection = 0;
        uint8_t lastStatus = 0;
        uint64_t streamId = 0;
        std::vector<HistEntry> hist;
    };

    static std::string sinkName(const MilanSink& s) {
        return idStr(s.listener) + ":" + std::to_string(s.uid);
    }

    /** Milan Table 5.5 probing status, derived from the sink state. */
    static const char* probingStatus(const std::string& st) {
        if (st.empty() || st == "UNBOUND") return "PROBING_DISABLED";
        if (st == "PRB_W_AVAIL") return "PROBING_PASSIVE";
        if (st == "SETTLED_NO_RSV" || st == "SETTLED_RSV_OK")
            return "PROBING_COMPLETED";
        return "PROBING_ACTIVE";
    }

    void sinkTransition(MilanSink& s, double ts, uint32_t n,
                        const std::string& to, const std::string& why) {
        std::string from = s.state.empty() ? "UNBOUND" : s.state;
        if (from == to) return;
        s.state = to;
        s.hist.push_back({ts, n, from, to, why});
        if (s.hist.size() > 200) s.hist.erase(s.hist.begin());
        Transition t;
        t.proto = Proto::ACMP;
        t.object = "milan sink " + sinkName(s);
        t.from = from;
        t.to = to;
        t.why = why;
        t.entity = idStr(s.listener);
        t.stream = s.streamId ? idStr(s.streamId) : "";
        std::string nm = mShared ? mShared->nameOf(s.listener) : "";
        t.summary = "Milan sink " + sinkName(s) +
                    (nm.empty() ? "" : " (" + nm + ")") + ": " + from + " -> " +
                    to + " — " + why;
        emit(std::move(t));
    }

    void sinkWarning(MilanSink& s, double ts, uint32_t n,
                     const std::string& why) {
        std::string st = s.state.empty() ? "UNBOUND" : s.state;
        s.hist.push_back({ts, n, st, st, why});
        if (s.hist.size() > 200) s.hist.erase(s.hist.begin());
        Transition t;
        t.proto = Proto::ACMP;
        t.object = "milan sink " + sinkName(s);
        t.from = st;
        t.to = st;
        t.why = why;
        t.entity = idStr(s.listener);
        t.summary = "Milan sink " + sinkName(s) + ": " + why;
        emit(std::move(t));
    }

    void talkerWarning(MilanTalker& t, double ts, uint32_t n,
                       const std::string& why) {
        t.hist.push_back({ts, n, "STATELESS", "STATELESS", why});
        if (t.hist.size() > 50) t.hist.erase(t.hist.begin());
        Transition tr;
        tr.proto = Proto::ACMP;
        tr.object = "milan talker " + idStr(t.talker) + ":" + std::to_string(t.uid);
        tr.from = "STATELESS";
        tr.to = "STATELESS";
        tr.why = why;
        tr.entity = idStr(t.talker);
        tr.summary = "Milan talker " + idStr(t.talker) + ":" +
                     std::to_string(t.uid) + ": " + why;
        emit(std::move(tr));
    }

    bool talkerAvailable(uint64_t talker) const {
        return mShared && mShared->adpAvailable.count(talker) != 0;
    }
    bool talkerAttrRegistered(uint64_t streamId) const {
        return mShared && mShared->msrpTalkerDecl.count(streamId) != 0;
    }

    void milanOnMessage(VarLayerContext& v, double ts, uint32_t n, uint8_t msg,
                        uint8_t status) {
        uint64_t listener = v.at("listener_entity_id");
        uint16_t lUid = (uint16_t)v.at("listener_unique_id");
        uint64_t talker = v.at("talker_entity_id");
        uint16_t tUid = (uint16_t)v.at("talker_unique_id");

        switch (msg) {
        case 6: { // BIND_RX_COMMAND (Milan name for CONNECT_RX_COMMAND)
            auto& s = mSinks[{listener, lUid}];
            s.listener = listener;
            s.uid = lUid;
            s.boundTalker = talker;
            s.boundTalkerUid = tUid;
            s.controller = v.at("controller_entity_id");
            s.talkerAvail = talkerAvailable(talker);
            sinkTransition(s, ts, n,
                           s.talkerAvail ? "PRB_W_DELAY" : "PRB_W_AVAIL",
                           "RCV_BIND_RX_CMD from controller " +
                               idStr(s.controller) + " (talker " +
                               (s.talkerAvail ? "already discovered"
                                              : "not yet discovered") + ")");
            break;
        }
        case 7: { // BIND_RX_RESPONSE
            auto it = mSinks.find({listener, lUid});
            if (it == mSinks.end()) break;
            if (status != 0)
                sinkTransition(it->second, ts, n, "UNBOUND",
                               "BIND_RX_RESPONSE " + acmpStatusName(status) +
                                   " — binding rejected");
            break;
        }
        case 8: { // UNBIND_RX_COMMAND
            auto& s = mSinks[{listener, lUid}];
            s.listener = listener;
            s.uid = lUid;
            sinkTransition(s, ts, n, "UNBOUND",
                           "RCV_UNBIND_RX_CMD from controller " +
                               idStr(v.at("controller_entity_id")));
            break;
        }
        case 0: { // PROBE_TX_COMMAND (Milan name for CONNECT_TX_COMMAND)
            auto& s = mSinks[{listener, lUid}];
            s.listener = listener;
            s.uid = lUid;
            s.probes++;
            auto& t = mTalkers[{talker, tUid}];
            t.talker = talker;
            t.uid = tUid;
            t.probesReceived++;
            std::string prev = s.state;
            if (prev == "PRB_W_RESP" &&
                ts - s.lastProbeTs < kMilanNoRespS + 0.3) {
                sinkTransition(s, ts, n, "PRB_W_RESP2",
                               "second PROBE_TX_COMMAND after TMR_NO_RESP (" +
                                   std::to_string((int)(
                                       (ts - s.lastProbeTs) * 1e3)) + " ms)");
            } else if (prev == "PRB_W_RETRY") {
                s.retryWarned = false;
                sinkTransition(s, ts, n, "PRB_W_RESP",
                               "TMR_RETRY expired — probing again");
            } else {
                std::string why = "PROBE_TX_COMMAND sent to talker " +
                                  idStr(talker);
                if (prev.empty() || prev == "UNBOUND") {
                    s.boundTalker = talker;
                    s.boundTalkerUid = tUid;
                    why += " without an observed BIND — saved binding restored"
                           " from non-volatile memory (Milan §5.5.2.4)";
                } else if (prev == "PRB_W_AVAIL") {
                    why += " (EVT_TK_DISCOVERED + TMR_DELAY inferred)";
                } else if (prev == "PRB_W_DELAY") {
                    why += " (TMR_DELAY expired)";
                }
                sinkTransition(s, ts, n, "PRB_W_RESP", why);
            }
            s.lastProbeTs = ts;
            break;
        }
        case 1: { // PROBE_TX_RESPONSE
            auto& t = mTalkers[{talker, tUid}];
            t.talker = talker;
            t.uid = tUid;
            t.probeResponses++;
            t.lastStatus = status;
            if (status == 0) t.streamId = v.at("stream_id");
            auto it = mSinks.find({listener, lUid});
            if (it == mSinks.end()) break;
            auto& s = it->second;
            if (status == 0) {
                s.streamId = v.at("stream_id");
                s.destMac = v.at("stream_dest_mac");
                s.vlan = (uint16_t)v.at("stream_vlan_id");
                s.settledNoRsvTs = ts;
                sinkTransition(s, ts, n, "SETTLED_NO_RSV",
                               "RCV_PROBE_TX_RESP SUCCESS — stream parameters"
                               " obtained (" + idStr(s.streamId) + ")");
                if (talkerAttrRegistered(s.streamId))
                    sinkTransition(s, ts, n, "SETTLED_RSV_OK",
                                   "EVT_TK_REGISTERED — matching talker"
                                   " attribute already registered (MSRP)");
            } else {
                sinkWarning(s, ts, n,
                            "PROBE_TX_RESPONSE " + acmpStatusName(status));
            }
            break;
        }
        case 2: { // DISCONNECT_TX_COMMAND — no talker state impact in Milan
            auto& t = mTalkers[{talker, tUid}];
            t.talker = talker;
            t.uid = tUid;
            t.disconnectTx++;
            break;
        }
        case 3: // DISCONNECT_TX_RESPONSE
            if (status != 0) {
                auto& t = mTalkers[{talker, tUid}];
                t.talker = talker;
                t.uid = tUid;
                talkerWarning(t, ts, n,
                              "DISCONNECT_TX_RESPONSE " +
                                  acmpStatusName(status) +
                                  " — Milan talkers always return SUCCESS"
                                  " (§5.5.4.2)");
            }
            break;
        case 12: { // GET_TX_CONNECTION_COMMAND — not implemented in Milan
            auto& t = mTalkers[{talker, tUid}];
            t.talker = talker;
            t.uid = tUid;
            t.getTxConnection++;
            talkerWarning(t, ts, n,
                          "GET_TX_CONNECTION_COMMAND observed — not"
                          " implemented by Milan talkers (§5.5.4.4)");
            break;
        }
        default:
            break;
        }
    }

    void milanTick(double ts) {
        for (auto& [key, s] : mSinks) {
            if (s.state.empty() || s.state == "UNBOUND") continue;

            // EVT_TK_DEPARTED / EVT_TK_DISCOVERED from ADP truth.
            bool avail = talkerAvailable(s.boundTalker);
            if (s.talkerAvail && !avail && s.state != "PRB_W_AVAIL") {
                s.talkerAvail = false;
                sinkTransition(s, ts, 0, "PRB_W_AVAIL",
                               "EVT_TK_DEPARTED — bound talker " +
                                   idStr(s.boundTalker) +
                                   " no longer AVAILABLE (ADP)");
                continue;
            }
            if (!s.talkerAvail && avail) {
                s.talkerAvail = true;
                if (s.state == "PRB_W_AVAIL")
                    sinkTransition(s, ts, 0, "PRB_W_DELAY",
                                   "EVT_TK_DISCOVERED (ADP) — waiting the"
                                   " random TMR_DELAY");
            }

            // EVT_TK_REGISTERED / EVT_TK_UNREGISTERED from MSRP truth.
            if (s.streamId) {
                bool reg = talkerAttrRegistered(s.streamId);
                if (s.state == "SETTLED_NO_RSV" && reg) {
                    sinkTransition(s, ts, 0, "SETTLED_RSV_OK",
                                   "EVT_TK_REGISTERED — talker attribute"
                                   " registered (MSRP)");
                } else if (s.state == "SETTLED_RSV_OK" && !reg) {
                    s.settledNoRsvTs = ts;
                    sinkTransition(s, ts, 0, "SETTLED_NO_RSV",
                                   "EVT_TK_UNREGISTERED — talker attribute"
                                   " unregistered (MSRP)");
                }
            }

            // Milan timers observed through capture time.
            if (s.state == "PRB_W_RESP2" &&
                ts > s.lastProbeTs + kMilanNoRespS + 0.05) {
                s.retryStartTs = ts;
                sinkTransition(s, ts, 0, "PRB_W_RETRY",
                               "TMR_NO_RESP expired twice — waiting TMR_RETRY"
                               " (4 s)");
            } else if (s.state == "PRB_W_RESP" &&
                       ts > s.lastProbeTs + kMilanNoRespS + 1.0) {
                s.retryStartTs = ts;
                sinkTransition(s, ts, 0, "PRB_W_RETRY",
                               "TMR_NO_RESP expired and no second PROBE_TX"
                               " observed (Milan §5.5.3 expects a retry)");
            } else if (s.state == "PRB_W_RETRY" && !s.retryWarned &&
                       ts > s.retryStartTs + kMilanRetryS + 1.0) {
                s.retryWarned = true;
                sinkWarning(s, ts, 0,
                            "TMR_RETRY (4 s) expired without a new PROBE_TX —"
                            " listener may have dropped the binding");
            } else if (s.state == "SETTLED_NO_RSV" &&
                       ts > s.settledNoRsvTs + kMilanNoTkS) {
                sinkTransition(s, ts, 0, "PRB_W_DELAY",
                               "TMR_NO_TK (10 s) — no matching talker"
                               " attribute registered, re-probing");
            }
        }
    }

    std::map<std::tuple<uint8_t, uint16_t, ConnKey>, Inflight> mInflight;
    std::map<ConnKey, Conn> mConns;
    std::map<std::pair<uint64_t, uint16_t>, MilanSink> mSinks;
    std::map<std::pair<uint64_t, uint16_t>, MilanTalker> mTalkers;
};

REGISTER_LOGIC("atdecc_acmp", AcmpLogic)

} // namespace
} // namespace avb
