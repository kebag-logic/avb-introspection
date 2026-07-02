/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * AECP command/response correlation (IEEE 1722.1 AEM): in-flight tracking
 * keyed (controller, target, sequence_id), 250 ms timeout per standard,
 * unsolicited-response counting, and entity-name learning for PA-6 from
 * READ_DESCRIPTOR(ENTITY), GET_NAME and SET_NAME responses.
 */
#include <deque>
#include <map>
#include <tuple>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

constexpr double kAemTimeoutS = 0.250;
constexpr uint16_t kCmdReadDescriptor = 0x0004;
constexpr uint16_t kCmdSetName = 0x0010;
constexpr uint16_t kCmdGetName = 0x0011;
constexpr uint16_t kDescEntity = 0x0000;

class AecpLogic final : public AvbLogicBase {
public:
    void onDecode(LayerContext& ctx) override {
        auto* v = dynamic_cast<VarLayerContext*>(&ctx);
        if (!v) return;
        double ts = tsOf(*v);
        uint32_t n = numOf(*v);
        uint8_t msg = (uint8_t)v->at("message_type");
        if (msg > 1) return; // only AEM command/response tracked in v1

        uint64_t target = v->at("target_entity_id");
        uint64_t controller = v->at("controller_entity_id");
        uint16_t seq = (uint16_t)v->at("sequence_id");
        uint16_t cmd = (uint16_t)v->at("command_type");
        uint8_t status = (uint8_t)v->at("status");
        bool unsolicited = v->at("unsolicited") != 0;

        auto& pair = mPairs[{controller, target}];

        if (msg == 0) { // AEM_COMMAND
            pair.commands++;
            mInflight[{controller, target, seq}] = {cmd, ts, n};
        } else { // AEM_RESPONSE
            if (unsolicited) {
                pair.unsolicited++;
            } else {
                auto it = mInflight.find({controller, target, seq});
                pair.responses++;
                Last l;
                l.seq = seq;
                l.cmd = cmd;
                l.status = status;
                if (it != mInflight.end()) {
                    l.rttMs = (ts - it->second.sentTs) * 1000.0;
                    mInflight.erase(it);
                } else {
                    l.rttMs = -1; // response without an observed command
                }
                pair.last.push_back(l);
                if (pair.last.size() > 10) pair.last.pop_front();
            }
            if (status == 0) learnName(*v, cmd, target, ts, n);
        }
    }

    void onTimeTick(double ts) override {
        for (auto it = mInflight.begin(); it != mInflight.end();) {
            if (ts > it->second.sentTs + kAemTimeoutS) {
                auto [controller, target, seq] = it->first;
                mPairs[{controller, target}].timeouts++;
                Transition t;
                t.proto = Proto::AECP;
                t.object = "aecp " + idStr(controller) + " -> " + idStr(target) +
                           " seq " + std::to_string(seq);
                t.from = "IN_FLIGHT";
                t.to = "TIMED_OUT";
                t.why = aemCommandName(it->second.cmd) +
                        " unanswered after 250 ms";
                t.entity = idStr(target);
                t.summary = "AEM " + aemCommandName(it->second.cmd) + " seq " +
                            std::to_string(seq) + " to " + idStr(target) +
                            " timed out (250 ms)";
                emit(std::move(t));
                it = mInflight.erase(it);
            } else {
                ++it;
            }
        }
    }

    void snapshot(JsonWriter& w) const override {
        w.key("aecp").beginArr();
        for (auto& [key, p] : mPairs) {
            w.beginObj();
            w.kv("controller", idStr(key.first));
            w.kv("target", idStr(key.second));
            w.kv("commands", (uint64_t)p.commands);
            w.kv("responses", (uint64_t)p.responses);
            w.kv("timeouts", (uint64_t)p.timeouts);
            w.kv("unsolicited", (uint64_t)p.unsolicited);
            w.key("last").beginArr();
            for (auto& l : p.last) {
                w.beginObj();
                w.kv("sequence_id", (uint64_t)l.seq);
                w.kv("command", aemCommandName(l.cmd));
                w.kv("status", aemStatusName(l.status));
                w.kv("rtt_ms", l.rttMs);
                w.endObj();
            }
            w.endArr();
            w.endObj();
        }
        w.endArr();
    }

private:
    struct Inflight {
        uint16_t cmd = 0;
        double sentTs = 0;
        uint32_t n = 0;
    };
    struct Last {
        uint16_t seq = 0, cmd = 0;
        uint8_t status = 0;
        double rttMs = 0;
    };
    struct Pair {
        uint32_t commands = 0, responses = 0, timeouts = 0, unsolicited = 0;
        std::deque<Last> last;
    };

    void learnName(VarLayerContext& v, uint16_t cmd, uint64_t target, double ts,
                   uint32_t n) {
        if (!mShared) return;
        std::string name;
        uint64_t entity = target;

        if (cmd == kCmdReadDescriptor &&
            v.at("descriptor_type") == kDescEntity &&
            v.getBytes("entity_name", name)) {
            uint64_t inner = v.at("entity_id");
            if (inner) entity = inner;
        } else if ((cmd == kCmdGetName || cmd == kCmdSetName) &&
                   v.at("descriptor_type") == kDescEntity &&
                   v.at("name_index") == 0 && v.getBytes("name", name)) {
            // entity == target
        } else {
            return;
        }

        auto& current = mShared->entityNames[entity];
        if (current == name || name.empty()) return;
        std::string from = current.empty() ? "(unnamed)" : current;
        current = name;

        Transition t;
        t.proto = Proto::AECP;
        t.object = "entity " + idStr(entity);
        t.from = from;
        t.to = name;
        t.why = "learned via AEM " + aemCommandName(cmd);
        t.entity = idStr(entity);
        t.summary = "Entity " + idStr(entity) + " named \"" + name + "\" (" +
                    aemCommandName(cmd) + ")";
        mPending.push_back(std::move(t));
        (void)ts;
        (void)n;
    }

    std::map<std::tuple<uint64_t, uint64_t, uint16_t>, Inflight> mInflight;
    std::map<std::pair<uint64_t, uint64_t>, Pair> mPairs;
};

REGISTER_LOGIC("atdecc_aecp", AecpLogic)

} // namespace
} // namespace avb
