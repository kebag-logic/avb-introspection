/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * MAAP address-range acquisition per claimant (IEEE 1722 Annex B):
 * PROBING -> ACQUIRED, DEFENDING on defence, LOST when a claimant abandons
 * a contested range and re-probes elsewhere.
 */
#include <map>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

class MaapLogic final : public AvbLogicBase {
public:
    void onDecode(LayerContext& ctx) override {
        auto* v = dynamic_cast<VarLayerContext*>(&ctx);
        if (!v) return;
        double ts = tsOf(*v);
        uint32_t n = numOf(*v);
        uint8_t msg = (uint8_t)v->at("message_type");
        uint64_t claimant = v->at("src_mac");
        uint64_t start = v->at("requested_start_address");
        uint16_t count = (uint16_t)v->at("requested_count");

        auto& r = mRanges[claimant];
        bool isNew = r.hist.empty() && r.state.empty();
        bool rangeChanged = !isNew && (r.start != start || r.count != count);

        if (rangeChanged && msg == 1 &&
            (r.state == "ACQUIRED" || r.state == "DEFENDING")) {
            transition(r, claimant, ts, n, "LOST",
                       "abandoned " + macStr(r.start) + " ×" +
                           std::to_string(r.count) + ", re-probing " +
                           macStr(start) + " ×" + std::to_string(count));
        }
        r.start = start;
        r.count = count;

        switch (msg) {
        case 1: // PROBE
            r.probes++;
            if (r.state != "PROBING")
                transition(r, claimant, ts, n, "PROBING",
                           "MAAP_PROBE " + macStr(start) + " ×" +
                               std::to_string(count));
            break;
        case 3: // ANNOUNCE
            if (r.state != "ACQUIRED")
                transition(r, claimant, ts, n, "ACQUIRED", "MAAP_ANNOUNCE");
            break;
        case 2: // DEFEND
            r.conflicts++;
            if (r.state != "DEFENDING")
                transition(r, claimant, ts, n, "DEFENDING",
                           "MAAP_DEFEND against conflicting claim on " +
                               macStr(v->at("conflict_start_address")) + " ×" +
                               std::to_string(v->at("conflict_count")));
            break;
        default:
            break;
        }
    }

    void snapshot(JsonWriter& w) const override {
        w.key("maap").beginArr();
        for (auto& [claimant, r] : mRanges) {
            w.beginObj();
            w.kv("claimant", macStr(claimant));
            w.kv("range_start", macStr(r.start));
            w.kv("count", (uint64_t)r.count);
            w.kv("state", r.state.empty() ? "UNKNOWN" : r.state);
            w.kv("conflicts", (uint64_t)r.conflicts);
            histJson(w, r.hist);
            w.endObj();
        }
        w.endArr();
    }

private:
    struct Range {
        uint64_t start = 0;
        uint16_t count = 0;
        uint32_t probes = 0, conflicts = 0;
        std::string state;
        std::vector<HistEntry> hist;
    };

    void transition(Range& r, uint64_t claimant, double ts, uint32_t n,
                    const std::string& to, const std::string& why) {
        std::string from = r.state.empty() ? "UNKNOWN" : r.state;
        r.state = to;
        r.hist.push_back({ts, n, from, to, why});
        Transition t;
        t.proto = Proto::MAAP;
        t.object = "maap " + macStr(claimant);
        t.from = from;
        t.to = to;
        t.why = why;
        t.stream = macStr(r.start);
        t.summary = "MAAP " + macStr(claimant) + ": " + from + " -> " + to + " — " +
                    why;
        emit(std::move(t));
    }

    std::map<uint64_t, Range> mRanges;
};

REGISTER_LOGIC("1722_maap", MaapLogic)

} // namespace
} // namespace avb
