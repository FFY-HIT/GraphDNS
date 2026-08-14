#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

// Semantic DNS graph builder and traverser.
//
// This file intentionally does not implement a live DNS resolver.  It compiles
// static records into a graph whose ordinary RR edges are always reachable, then
// derives Org/Del/DRew/CRew edges and labels only those semantic edges with the
// reach rules from the design.

namespace semantic_dns {

static const std::string kAlphaPrefix = "\xCE\xB1."; // UTF-8 "alpha."
static const std::string kBetaPrefix = "\xCE\xB2.";  // UTF-8 "beta."
static const std::string kOriginName = "Origin";

enum class NodeKind : uint8_t {
    Origin,
    Alpha,
    Beta,
    Wildcard,
    Concrete,
    Terminal
};

enum class EdgeType : uint8_t {
    NS,
    A,
    AAAA,
    CNAME,
    DNAME,
    MX,
    TXT,
    Org,
    Del,
    DRew,
    CRew,
    Other
};

struct Server {
    int id = -1;
    std::string name;
    std::vector<int> zones;
};

struct Zone {
    int id = -1;
    std::string origin;
    int server = -1;
    std::vector<int> nodes;
    std::vector<int> edges;
    std::unordered_map<std::string, int> node_by_name;
};

struct Node {
    int id = -1;
    std::string name;
    int server = -1;
    int zone = -1;
    NodeKind kind = NodeKind::Concrete;
};

struct Edge {
    int id = -1;
    int src = -1;
    int dst = -1;
    EdgeType type = EdgeType::Other;
    int reach = 0;
    std::string record;
    bool deleted = false;
    bool forced_unreachable = false;
};

static void hash_combine_value(size_t& seed, size_t value) {
    seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

struct ZoneKey {
    int server = -1;
    std::string origin;

    bool operator==(const ZoneKey& other) const {
        return server == other.server && origin == other.origin;
    }
};

struct ZoneKeyHash {
    size_t operator()(const ZoneKey& k) const {
        size_t h = std::hash<int>{}(k.server);
        hash_combine_value(h, std::hash<std::string>{}(k.origin));
        return h;
    }
};

struct EdgeKey {
    int src = -1;
    int dst = -1;
    EdgeType type = EdgeType::Other;
    std::string record;

    bool operator==(const EdgeKey& other) const {
        return src == other.src &&
               dst == other.dst &&
               type == other.type &&
               record == other.record;
    }
};

struct EdgeKeyHash {
    size_t operator()(const EdgeKey& k) const {
        size_t h = std::hash<int>{}(k.src);
        hash_combine_value(h, std::hash<int>{}(k.dst));
        hash_combine_value(h, std::hash<int>{}(static_cast<int>(k.type)));
        hash_combine_value(h, std::hash<std::string>{}(k.record));
        return h;
    }
};

struct IntStringPairHash {
    size_t operator()(const std::pair<int, std::string>& k) const {
        size_t h = std::hash<int>{}(k.first);
        hash_combine_value(h, std::hash<std::string>{}(k.second));
        return h;
    }
};

class IdMarker {
public:
    explicit IdMarker(size_t size = 0) : marks_(size, 0) {}

    void resize(size_t size) {
        marks_.assign(size, 0);
        token_ = 1;
    }

    void ensure_size(size_t size) {
        if (marks_.size() < size) marks_.resize(size, 0);
    }

    void next() {
        ++token_;
        if (token_ == 0) {
            std::fill(marks_.begin(), marks_.end(), 0);
            token_ = 1;
        }
    }

    bool mark(int id) {
        if (id < 0 || id >= static_cast<int>(marks_.size())) return false;
        uint32_t& slot = marks_[id];
        if (slot == token_) return false;
        slot = token_;
        return true;
    }

private:
    std::vector<uint32_t> marks_;
    uint32_t token_ = 1;
};

struct RecordInput {
    std::string server;
    std::string zone;
    std::string owner;
    EdgeType type = EdgeType::Other;
    std::string rdata;
};

struct SemanticGraph {
    std::vector<Server> servers;
    std::vector<Zone> zones;
    std::vector<Node> nodes;
    std::vector<Edge> edges;
    std::unordered_map<std::string, int> server_by_name;
    std::unordered_map<ZoneKey, int, ZoneKeyHash> zone_by_server_origin;
    std::unordered_map<int, std::vector<int>> outgoing_edges;
    std::unordered_map<int, int> semantic_edge_origin;
    std::unordered_map<int, std::vector<int>> induced_edge_index;
    int origin_node = -1;
};

static std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = char(c | 0x20);
    }
    return s;
}

static std::string trim(std::string s) {
    size_t l = 0;
    size_t r = s.size();
    while (l < r && std::isspace(static_cast<unsigned char>(s[l]))) ++l;
    while (r > l && std::isspace(static_cast<unsigned char>(s[r - 1]))) --r;
    return s.substr(l, r - l);
}

static bool looks_like_ip_or_literal(const std::string& s) {
    if (s.empty()) return true;
    if (s.front() == '"' || s.find(':') != std::string::npos) return true;
    bool has_digit = false;
    bool only_ipv4_chars = true;
    for (char c : s) {
        if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
        if (!(std::isdigit(static_cast<unsigned char>(c)) || c == '.')) {
            only_ipv4_chars = false;
        }
    }
    return has_digit && only_ipv4_chars;
}

static std::string normalize_domain(std::string s) {
    s = to_lower_ascii(trim(std::move(s)));
    if (!s.empty() && s.back() != '.' && !looks_like_ip_or_literal(s)) {
        s.push_back('.');
    }
    return s;
}

static bool ends_with(std::string_view s, std::string_view suffix) {
    if (suffix.size() > s.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

static bool is_descendant_or_same(const std::string& child, const std::string& ancestor) {
    if (child == ancestor) return true;
    if (ancestor == ".") return child != ".";
    return ends_with(child, "." + ancestor);
}

static bool is_strict_descendant_of(const std::string& child, const std::string& ancestor) {
    return child != ancestor && is_descendant_or_same(child, ancestor);
}

static bool is_immediate_child_of(const std::string& child, const std::string& parent) {
    if (child == parent) return false;
    if (!is_descendant_or_same(child, parent)) return false;

    if (parent == ".") {
        if (child.empty() || child.back() != '.') return false;
        std::string label = child.substr(0, child.size() - 1);
        return !label.empty() && label.find('.') == std::string::npos;
    }

    const size_t suffix_len = parent.size();
    if (child.size() <= suffix_len + 1) return false;

    std::string label = child.substr(0, child.size() - suffix_len);
    if (!label.empty() && label.back() == '.') {
        label.pop_back();
    }

    return !label.empty() && label.find('.') == std::string::npos;
}

static std::vector<std::string> ancestor_suffixes_inclusive(const std::string& name) {
    std::vector<std::string> out;
    if (name.empty()) return out;
    out.push_back(name);
    if (name == ".") return out;

    size_t pos = 0;
    while (true) {
        pos = name.find('.', pos);
        if (pos == std::string::npos) break;
        std::string suffix = (pos + 1 < name.size()) ? name.substr(pos + 1) : ".";
        if (out.empty() || out.back() != suffix) {
            out.push_back(std::move(suffix));
        }
        if (pos + 1 >= name.size()) break;
        ++pos;
    }
    return out;
}

static std::vector<std::string> ancestor_suffixes_proper(const std::string& name) {
    std::vector<std::string> out = ancestor_suffixes_inclusive(name);
    if (!out.empty()) out.erase(out.begin());
    return out;
}

static std::optional<std::string> immediate_parent_suffix(const std::string& name) {
    if (name.empty() || name == ".") return std::nullopt;
    size_t pos = name.find('.');
    if (pos == std::string::npos) return std::nullopt;
    if (pos + 1 >= name.size()) return std::string(".");
    return name.substr(pos + 1);
}

static bool symbolic_query_matches_name(const std::string& pattern,
                                        const std::string& name) {
    if (pattern == name) return true;
    if (pattern.rfind("_.", 0) == 0) {
        return is_strict_descendant_of(name, pattern.substr(2));
    }
    if (name.rfind("_.", 0) == 0) {
        return is_strict_descendant_of(pattern, name.substr(2));
    }
    return is_descendant_or_same(pattern, name) ||
           is_descendant_or_same(name, pattern);
}

static std::optional<std::string> beta_prefix_for_query(const std::string& q,
                                                        const std::string& suffix) {
    if (is_strict_descendant_of(q, suffix)) {
        std::string prefix = q.substr(0, q.size() - suffix.size());
        if (!prefix.empty() && prefix.back() == '.') {
            prefix.pop_back();
        }
        if (!prefix.empty()) return prefix;
    }

    if (is_strict_descendant_of(suffix, q)) {
        return std::string("_");
    }

    return std::nullopt;
}

static bool beta_prefixes_compatible(const std::string& a, const std::string& b) {
    return a == b || a == "_" || b == "_";
}

static std::string strip_prefix(const std::string& name, const std::string& prefix) {
    if (name.rfind(prefix, 0) == 0) return name.substr(prefix.size());
    return name;
}

static std::string alpha_name(const std::string& suffix) {
    return kAlphaPrefix + normalize_domain(suffix);
}

static std::string beta_name(const std::string& suffix) {
    return kBetaPrefix + normalize_domain(suffix);
}

static bool is_base_type(EdgeType t) {
    return t == EdgeType::NS ||
           t == EdgeType::A ||
           t == EdgeType::AAAA ||
           t == EdgeType::CNAME ||
           t == EdgeType::DNAME ||
           t == EdgeType::MX ||
           t == EdgeType::TXT;
}

static bool is_semantic_type(EdgeType t) {
    return t == EdgeType::Org ||
           t == EdgeType::Del ||
           t == EdgeType::DRew ||
           t == EdgeType::CRew;
}

static std::string edge_type_name(EdgeType t) {
    switch (t) {
        case EdgeType::NS: return "NS";
        case EdgeType::A: return "A";
        case EdgeType::AAAA: return "AAAA";
        case EdgeType::CNAME: return "CNAME";
        case EdgeType::DNAME: return "DNAME";
        case EdgeType::MX: return "MX";
        case EdgeType::TXT: return "TXT";
        case EdgeType::Org: return "org";
        case EdgeType::Del: return "Del";
        case EdgeType::DRew: return "DRew";
        case EdgeType::CRew: return "CRew";
        default: return "Other";
    }
}

static bool ascii_ieq(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'a' && ca <= 'z') ca = static_cast<unsigned char>(ca - 'a' + 'A');
        if (cb >= 'a' && cb <= 'z') cb = static_cast<unsigned char>(cb - 'a' + 'A');
        if (ca != cb) return false;
    }
    return true;
}

static EdgeType parse_edge_type(std::string_view t) {
    if (ascii_ieq(t, "NS")) return EdgeType::NS;
    if (ascii_ieq(t, "A")) return EdgeType::A;
    if (ascii_ieq(t, "AAAA")) return EdgeType::AAAA;
    if (ascii_ieq(t, "CNAME")) return EdgeType::CNAME;
    if (ascii_ieq(t, "DNAME")) return EdgeType::DNAME;
    if (ascii_ieq(t, "MX")) return EdgeType::MX;
    if (ascii_ieq(t, "TXT")) return EdgeType::TXT;
    return EdgeType::Other;
}

class SemanticHelpers {
public:
    explicit SemanticHelpers(const SemanticGraph& graph) : graph_(graph) {
        suffix_cache_.resize(graph_.nodes.size());
        stripped_cache_.resize(graph_.nodes.size());
        suffix_ready_.assign(graph_.nodes.size(), 0);
        stripped_ready_.assign(graph_.nodes.size(), 0);
    }

    bool IsAlpha(int v) const { return graph_.nodes[v].kind == NodeKind::Alpha; }
    bool IsBeta(int v) const { return graph_.nodes[v].kind == NodeKind::Beta; }
    bool IsOrigin(int v) const { return graph_.nodes[v].kind == NodeKind::Origin; }
    bool IsWildcard(int v) const { return graph_.nodes[v].kind == NodeKind::Wildcard; }
    bool IsConcrete(int v) const { return graph_.nodes[v].kind == NodeKind::Concrete; }

    const std::string& suffix_ref(int v) const {
        ensure_cache_size(v);
        if (!suffix_ready_[v]) {
            suffix_cache_[v] = compute_suffix(v);
            suffix_ready_[v] = 1;
        }
        return suffix_cache_[v];
    }

    std::string suffix(int v) const {
        return suffix_ref(v);
    }

    const std::string& symbolic_stripped_name_ref(int v) const {
        ensure_cache_size(v);
        if (!stripped_ready_[v]) {
            stripped_cache_[v] = compute_symbolic_stripped_name(v);
            stripped_ready_[v] = 1;
        }
        return stripped_cache_[v];
    }

    std::string symbolic_stripped_name(int v) const {
        return symbolic_stripped_name_ref(v);
    }

private:
    const SemanticGraph& graph_;
    mutable std::vector<std::string> suffix_cache_;
    mutable std::vector<std::string> stripped_cache_;
    mutable std::vector<uint8_t> suffix_ready_;
    mutable std::vector<uint8_t> stripped_ready_;

    void ensure_cache_size(int v) const {
        if (v < 0) return;
        const size_t need = static_cast<size_t>(v) + 1;
        if (suffix_cache_.size() >= need) return;
        suffix_cache_.resize(need);
        stripped_cache_.resize(need);
        suffix_ready_.resize(need, 0);
        stripped_ready_.resize(need, 0);
    }

    std::string compute_suffix(int v) const {
        const Node& n = graph_.nodes[v];
        if (n.kind == NodeKind::Origin) return "";
        if (n.kind == NodeKind::Alpha) return strip_prefix(n.name, kAlphaPrefix);
        if (n.kind == NodeKind::Beta) return strip_prefix(n.name, kBetaPrefix);
        if (n.kind == NodeKind::Wildcard && n.name.rfind("*.", 0) == 0) {
            return n.name.substr(2);
        }
        if (n.kind == NodeKind::Concrete) {
            const Zone& z = graph_.zones[n.zone];
            if (is_descendant_or_same(n.name, z.origin)) return z.origin;
        }
        return n.name;
    }

    std::string compute_symbolic_stripped_name(int v) const {
        const Node& n = graph_.nodes[v];
        if (n.kind == NodeKind::Origin) return "";
        if (n.kind == NodeKind::Alpha) return strip_prefix(n.name, kAlphaPrefix);
        if (n.kind == NodeKind::Beta) return strip_prefix(n.name, kBetaPrefix);
        if (n.kind == NodeKind::Wildcard && n.name.rfind("*.", 0) == 0) return n.name.substr(2);
        return n.name;
    }

public:

    bool sameSuffix(int v1, int v2) const {
        const std::string& s1 = suffix_ref(v1);
        const std::string& s2 = suffix_ref(v2);
        if (s1 == s2) return true;

        // Concrete owners represent queries under their zone suffix.  This
        // keeps examples such as sameSuffix(alpha.coinsbank.com.,
        // m.coinsbank.com.) true without globally merging the nodes.
        return concrete_or_wildcard_name_has_suffix(v1, s2) ||
               concrete_or_wildcard_name_has_suffix(v2, s1);
    }

    bool isAncestorSuffix(int a, int b) const {
        const std::string& as = suffix_ref(a);
        const std::string& bs = suffix_ref(b);
        return as != bs && is_descendant_or_same(bs, as);
    }

    bool alphaMatches(int alpha, int v) const {
        if (!IsAlpha(alpha)) return false;
        if (graph_.nodes[v].kind == NodeKind::Terminal) return false;
        return is_descendant_or_same(symbolic_stripped_name_ref(v), suffix_ref(alpha));
    }

    bool betaMatches(int beta, int v) const {
        if (!IsBeta(beta)) return false;
        if (graph_.nodes[v].kind == NodeKind::Terminal) return false;

        if (IsBeta(v)) {
            const std::string& bs = suffix_ref(beta);
            const std::string& vs = suffix_ref(v);
            return bs == vs || is_descendant_or_same(vs, bs);
        }

        // A beta label binds to one or more labels before its suffix.
        return is_strict_descendant_of(symbolic_stripped_name_ref(v), suffix_ref(beta));
    }

    bool betaTargetCompatible(int source_beta, int target_beta) const {
        if (!IsBeta(source_beta) || !IsBeta(target_beta)) return false;
        const std::string& source_suffix = suffix_ref(source_beta);
        const std::string& target_suffix = suffix_ref(target_beta);
        return source_suffix == target_suffix ||
               is_descendant_or_same(source_suffix, target_suffix) ||
               is_descendant_or_same(target_suffix, source_suffix);
    }

    bool dnameTargetNameMatches(int source_beta, int target) const {
        if (!IsBeta(source_beta)) return false;
        if (graph_.nodes[target].kind == NodeKind::Terminal) return false;

        const std::string& source_suffix = suffix_ref(source_beta);
        const std::string& target_name = symbolic_stripped_name_ref(target);

        if (IsWildcard(target)) {
            return target_name == source_suffix ||
                   is_descendant_or_same(target_name, source_suffix);
        }

        // DNAME rewrites beta.owner to beta.rdata.  The beta prefix represents
        // one or more labels, so a concrete target at exactly rdata is not a
        // valid DRew successor; only concrete descendants such as x.rdata are.
        return is_strict_descendant_of(target_name, source_suffix);
    }

    bool HasOwnerOutgoing(int v) const {
        auto it = graph_.outgoing_edges.find(v);
        if (it == graph_.outgoing_edges.end()) return false;
        for (int eid : it->second) {
            if (graph_.edges[eid].deleted) continue;
            if (is_base_type(graph_.edges[eid].type)) return true;
        }
        return false;
    }

    bool ExistsAlphaWithSameSuffix(int server, int zone, int v) const {
        if (zone < 0 || zone >= static_cast<int>(graph_.zones.size())) return false;
        const Zone& z = graph_.zones[zone];
        if (z.server != server) return false;

        for (int nid : z.nodes) {
            if (IsAlpha(nid) && alphaMatches(nid, v)) return true;
        }
        return false;
    }

    bool ExistsBetaWithSameSuffix(int server, int zone, int v) const {
        if (zone < 0 || zone >= static_cast<int>(graph_.zones.size())) return false;
        const Zone& z = graph_.zones[zone];
        if (z.server != server) return false;

        for (int nid : z.nodes) {
            if (!HasOwnerOutgoing(nid)) continue;
            if (IsBeta(nid) && sameSuffix(nid, v)) return true;
        }
        return false;
    }

    bool ExistsConcreteCoveredByWildcard(int server, int wildcard) const {
        for (int zid : graph_.servers[server].zones) {
            for (int nid : graph_.zones[zid].nodes) {
                if (!HasOwnerOutgoing(nid)) continue;
                if (IsConcrete(nid) && wildcardCovers(wildcard, nid)) return true;
            }
        }
        return false;
    }

    bool ExistsConcreteOwnerNamed(int server, const std::string& name) const {
        for (int zid : graph_.servers[server].zones) {
            for (int nid : graph_.zones[zid].nodes) {
                if (!IsConcrete(nid)) continue;
                if (!HasOwnerOutgoing(nid)) continue;
                if (graph_.nodes[nid].name == name) return true;
            }
        }
        return false;
    }

    bool ExistsLocalCover(int server, int v) const {
        for (int zid : graph_.servers[server].zones) {
            for (int u : graph_.zones[zid].nodes) {
                if (!HasOwnerOutgoing(u)) continue;
                if (graph_.nodes[u].name == graph_.nodes[v].name) return true;
                if (IsWildcard(u) && wildcardCovers(u, v)) return true;
                if (IsBeta(u) && sameSuffix(u, v)) return true;
            }
        }
        return false;
    }

    bool ExistsNonAlphaLocalCover(int server, int v) const {
        for (int zid : graph_.servers[server].zones) {
            for (int u : graph_.zones[zid].nodes) {
                if (!HasOwnerOutgoing(u)) continue;
                if (IsAlpha(u)) continue;
                if (graph_.nodes[u].name == graph_.nodes[v].name) return true;
                if (IsWildcard(u) && wildcardCovers(u, v)) return true;
            }
        }
        return false;
    }

    bool wildcardCovers(int wildcard, int v) const {
        if (!IsWildcard(wildcard)) return false;
        if (graph_.nodes[v].kind == NodeKind::Terminal) return false;
        const std::string& enc = suffix_ref(wildcard);
        const std::string& name = symbolic_stripped_name_ref(v);
        // DNS wildcards match exactly one label below their enclosing name:
        // *.example. covers a.example., but not example. or a.b.example.
        return is_immediate_child_of(name, enc);
    }

    bool concrete_or_wildcard_name_has_suffix(int v, const std::string& s) const {
        const Node& n = graph_.nodes[v];
        if (n.kind != NodeKind::Concrete && n.kind != NodeKind::Wildcard) return false;
        return is_descendant_or_same(symbolic_stripped_name_ref(v), s);
    }

};

class GraphBuilder {
public:
    GraphBuilder() = default;

    struct BuildTiming {
        double base_seconds = 0.0;
        double semantic_seconds = 0.0;
        double invariant_seconds = 0.0;
    };

    struct SemanticBuildStats {
        size_t owner_nodes = 0;
        size_t base_ns = 0;
        size_t base_cname = 0;
        size_t base_dname = 0;
        size_t del_candidates_checked = 0;
        size_t crew_candidates_checked = 0;
        size_t drew_candidates_checked = 0;
        size_t del_edges_added = 0;
        size_t crew_edges_added = 0;
        size_t drew_edges_added = 0;
    };

    void addRecord(const std::string& server,
                   const std::string& zone,
                   const std::string& owner,
                   EdgeType type,
                   const std::string& rdata) {
        if (!is_base_type(type)) return;
        records_.push_back(RecordInput{
            normalize_domain(server),
            normalize_domain(zone),
            normalize_domain(owner),
            type,
            normalize_rdata(type, rdata)
        });
    }

    void loadFacts(const std::string& path) {
        std::ifstream in(path);
        if (!in.is_open()) {
            throw std::runtime_error("Cannot open facts file: " + path);
        }
        in.seekg(0, std::ios::end);
        const std::streamoff bytes = in.tellg();
        if (bytes > 0) {
            records_.reserve(records_.size() + static_cast<size_t>(bytes / 64) + 1);
        }
        in.seekg(0, std::ios::beg);

        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            const size_t p1 = line.find('\t');
            if (p1 == std::string::npos) continue;
            const size_t p2 = line.find('\t', p1 + 1);
            if (p2 == std::string::npos) continue;
            const size_t p3 = line.find('\t', p2 + 1);
            if (p3 == std::string::npos) continue;
            const size_t p4 = line.find('\t', p3 + 1);
            if (p4 == std::string::npos) continue;
            if (line.find('\t', p4 + 1) != std::string::npos) continue;

            addRecord(line.substr(0, p1),
                      line.substr(p1 + 1, p2 - p1 - 1),
                      line.substr(p2 + 1, p3 - p2 - 1),
                      parse_edge_type(std::string_view(line).substr(p3 + 1, p4 - p3 - 1)),
                      line.substr(p4 + 1));
        }
    }

    SemanticGraph build(BuildTiming* timing = nullptr,
                        bool validate_invariants = false,
                        SemanticBuildStats* semantic_stats = nullptr) {
        using Clock = std::chrono::steady_clock;
        auto seconds = [](Clock::time_point a, Clock::time_point b) {
            return std::chrono::duration<double>(b - a).count();
        };

        graph_ = SemanticGraph{};
        edge_by_key_.clear();
        graph_.servers.reserve(records_.size());
        graph_.zones.reserve(records_.size());
        graph_.nodes.reserve(records_.size() * 2 + 8);
        graph_.edges.reserve(records_.size() * 4 + 16);
        graph_.server_by_name.reserve(records_.size() * 2 + 1);
        graph_.zone_by_server_origin.reserve(records_.size() * 2 + 1);
        edge_by_key_.reserve(records_.size() * 4 + 16);
        auto t0 = Clock::now();
        for (const RecordInput& r : records_) {
            add_base_record(r);
        }
        auto t1 = Clock::now();
        if (validate_invariants) {
            validate_graph_invariants("after base record construction");
        }
        auto t2 = Clock::now();
        build_semantic_edges(semantic_stats);
        build_origin_edges();
        auto t3 = Clock::now();
        if (validate_invariants) {
            validate_graph_invariants("after semantic edge construction");
        }
        auto t4 = Clock::now();
        if (timing) {
            timing->base_seconds = seconds(t0, t1);
            timing->semantic_seconds = seconds(t2, t3);
            timing->invariant_seconds = seconds(t1, t2) + seconds(t3, t4);
        }
        return std::move(graph_);
    }

private:
    std::vector<RecordInput> records_;
    SemanticGraph graph_;
    std::unordered_map<EdgeKey, int, EdgeKeyHash> edge_by_key_;

    static void split_tab(const std::string& line, std::vector<std::string>& cols) {
        size_t start = 0;
        while (true) {
            size_t pos = line.find('\t', start);
            if (pos == std::string::npos) {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
    }

    static std::string normalize_rdata(EdgeType type, const std::string& rdata) {
        if (type == EdgeType::A || type == EdgeType::AAAA || type == EdgeType::TXT) {
            return trim(rdata);
        }
        // The design treats MX targets as terminal values, but the value still
        // uses domain-name normalization for stable comparisons and printing.
        if (type == EdgeType::MX ||
            type == EdgeType::NS ||
            type == EdgeType::CNAME ||
            type == EdgeType::DNAME) {
            return normalize_domain(rdata);
        }
        return trim(rdata);
    }

    int ensure_server(const std::string& name) {
        auto it = graph_.server_by_name.find(name);
        if (it != graph_.server_by_name.end()) return it->second;
        int id = static_cast<int>(graph_.servers.size());
        graph_.servers.push_back(Server{id, name, {}});
        graph_.server_by_name[name] = id;
        return id;
    }

    int ensure_zone(int server, const std::string& origin) {
        ZoneKey key{server, origin};
        auto it = graph_.zone_by_server_origin.find(key);
        if (it != graph_.zone_by_server_origin.end()) return it->second;
        int id = static_cast<int>(graph_.zones.size());
        graph_.zones.push_back(Zone{id, origin, server, {}, {}, {}});
        graph_.zone_by_server_origin.emplace(std::move(key), id);
        graph_.servers[server].zones.push_back(id);
        return id;
    }

    static int kind_rank(NodeKind k) {
        switch (k) {
            case NodeKind::Origin: return 6;
            case NodeKind::Alpha: return 5;
            case NodeKind::Beta: return 4;
            case NodeKind::Wildcard: return 3;
            case NodeKind::Concrete: return 2;
            case NodeKind::Terminal: return 1;
        }
        return 0;
    }

    int ensure_node(int server, int zone, const std::string& name, NodeKind requested_kind) {
        Zone& z = graph_.zones[zone];
        auto it = z.node_by_name.find(name);
        if (it != z.node_by_name.end()) {
            int id = it->second;
            const Node& existing = graph_.nodes[id];
            if (existing.server != server || existing.zone != zone || existing.name != name) {
                throw std::runtime_error("node uniqueness index is corrupt for " + name);
            }
            // Same server+zone+name is unique.  If the name later appears as an
            // owner, keep the single node and promote it from terminal.
            if (kind_rank(requested_kind) > kind_rank(graph_.nodes[id].kind)) {
                graph_.nodes[id].kind = requested_kind;
            }
            return id;
        }

        int id = static_cast<int>(graph_.nodes.size());
        graph_.nodes.push_back(Node{id, name, server, zone, requested_kind});
        z.node_by_name[name] = id;
        z.nodes.push_back(id);
        return id;
    }

    void validate_graph_invariants(const std::string& phase) const {
        for (const Zone& z : graph_.zones) {
            std::unordered_map<std::string, int> seen;
            seen.reserve(z.nodes.size() * 2 + 1);

            for (int nid : z.nodes) {
                if (nid < 0 || nid >= static_cast<int>(graph_.nodes.size())) {
                    throw std::runtime_error("invalid node id in zone during " + phase);
                }

                const Node& n = graph_.nodes[nid];
                if (n.server != z.server || n.zone != z.id) {
                    throw std::runtime_error("node context mismatch for " + n.name +
                                             " during " + phase);
                }

                auto inserted = seen.emplace(n.name, nid);
                if (!inserted.second && inserted.first->second != nid) {
                    throw std::runtime_error("duplicate node name in same server+zone during " +
                                             phase + ": " + n.name);
                }

                auto indexed = z.node_by_name.find(n.name);
                if (indexed == z.node_by_name.end() || indexed->second != nid) {
                    throw std::runtime_error("missing node uniqueness index for " + n.name +
                                             " during " + phase);
                }
            }

            if (seen.size() != z.node_by_name.size()) {
                throw std::runtime_error("zone node uniqueness index has stale entries during " +
                                         phase);
            }
        }

        for (const Edge& e : graph_.edges) {
            if (e.src < 0 || e.src >= static_cast<int>(graph_.nodes.size()) ||
                e.dst < 0 || e.dst >= static_cast<int>(graph_.nodes.size())) {
                throw std::runtime_error("edge references invalid node during " + phase);
            }

            const Node& src = graph_.nodes[e.src];
            const Node& dst = graph_.nodes[e.dst];

            if (dst.kind == NodeKind::Alpha && e.type != EdgeType::Org) {
                throw std::runtime_error("edge points to alpha during " + phase +
                                         ": " + src.name + " -> " + dst.name);
            }

            if (src.kind == NodeKind::Origin && e.type != EdgeType::Org) {
                throw std::runtime_error("Origin node has a non-org outgoing edge during " +
                                         phase);
            }

            if (is_base_type(e.type) &&
                (src.server != dst.server || src.zone != dst.zone)) {
                throw std::runtime_error("base RR edge crosses server/zone during " + phase +
                                         ": " + src.name + " -> " + dst.name);
            }

            if (e.type == EdgeType::CRew && e.src == e.dst) {
                throw std::runtime_error("CRew self-loop during " + phase +
                                         ": " + src.name);
            }
        }
    }

    int add_edge(int src,
                 int dst,
                 EdgeType type,
                 const std::string& record,
                 int origin = -1,
                 bool forced_unreachable = false) {
        // Alpha nodes remain unavailable as ordinary semantic destinations;
        // the graph-level Origin is the only node allowed to point to them.
        if (graph_.nodes[dst].kind == NodeKind::Alpha && type != EdgeType::Org) {
            return -1;
        }
        if (type == EdgeType::CRew && src == dst) {
            return -1;
        }

        EdgeKey key{src, dst, type, record};
        auto existing = edge_by_key_.find(key);
        if (existing != edge_by_key_.end()) {
            int id = existing->second;
            if (forced_unreachable) {
                graph_.edges[id].forced_unreachable = true;
            }
            return id;
        }

        int id = static_cast<int>(graph_.edges.size());
        graph_.edges.push_back(Edge{id, src, dst, type, 0, record, false, forced_unreachable});
        edge_by_key_.emplace(std::move(key), id);
        if (graph_.nodes[src].zone >= 0) {
            graph_.zones[graph_.nodes[src].zone].edges.push_back(id);
        }
        graph_.outgoing_edges[src].push_back(id);
        if (origin >= 0) {
            graph_.semantic_edge_origin[id] = origin;
            graph_.induced_edge_index[origin].push_back(id);
        }
        return id;
    }

    static NodeKind classify_owner(const std::string& name) {
        if (name.rfind(kAlphaPrefix, 0) == 0) return NodeKind::Alpha;
        if (name.rfind(kBetaPrefix, 0) == 0) return NodeKind::Beta;
        if (name.rfind("*.", 0) == 0) return NodeKind::Wildcard;
        return NodeKind::Concrete;
    }

    static NodeKind classify_rr_target(EdgeType type, const std::string& name) {
        if (type == EdgeType::A || type == EdgeType::AAAA || type == EdgeType::TXT ||
            type == EdgeType::MX) {
            return NodeKind::Terminal;
        }
        return classify_owner(name);
    }

    void add_base_record(const RecordInput& r) {
        int server = ensure_server(r.server);
        int zone = ensure_zone(server, r.zone);

        std::string src_name = r.owner;
        std::string dst_name = r.rdata;
        NodeKind src_kind = classify_owner(src_name);
        NodeKind dst_kind = classify_rr_target(r.type, dst_name);

        // NS owners are alpha nodes: u NS h becomes alpha.u --NS--> h.
        if (r.type == EdgeType::NS) {
            src_name = alpha_name(r.owner);
            src_kind = NodeKind::Alpha;
            dst_kind = NodeKind::Concrete;
        }

        // DNAME owners and rdata are beta nodes: owner DNAME rdata becomes
        // beta.owner --DNAME--> beta.rdata.
        if (r.type == EdgeType::DNAME) {
            src_name = beta_name(r.owner);
            dst_name = beta_name(r.rdata);
            src_kind = NodeKind::Beta;
            dst_kind = NodeKind::Beta;
        }

        int src = ensure_node(server, zone, src_name, src_kind);
        int dst = ensure_node(server, zone, dst_name, dst_kind);

        std::ostringstream rec;
        rec << r.owner << " " << edge_type_name(r.type) << " " << r.rdata;
        add_edge(src, dst, r.type, rec.str());
    }

    void build_semantic_edges(SemanticBuildStats* stats = nullptr) {
        SemanticHelpers h(graph_);
        std::vector<Edge> base_edges = graph_.edges;
        SemanticCandidateIndex index;
        collect_owner_nodes(h, index);
        IdMarker candidate_marker(graph_.nodes.size());
        if (stats) {
            stats->owner_nodes = index.owner_nodes.size();
        }

        for (const Edge& e : base_edges) {
            if (e.type == EdgeType::NS) {
                if (stats) ++stats->base_ns;
                candidate_marker.next();
                build_del_edges(e, h, index, candidate_marker, stats);
            }
        }
        for (const Edge& e : base_edges) {
            if (e.type == EdgeType::DNAME) {
                if (stats) ++stats->base_dname;
                candidate_marker.next();
                build_drew_edges(e, h, index, candidate_marker, stats);
            }
        }
        for (const Edge& e : base_edges) {
            if (e.type == EdgeType::CNAME) {
                if (stats) ++stats->base_cname;
                candidate_marker.next();
                build_crew_edges(e, h, index, candidate_marker, stats);
            }
        }
    }

    void build_origin_edges() {
        if (graph_.origin_node < 0) {
            graph_.origin_node = static_cast<int>(graph_.nodes.size());
            graph_.nodes.push_back(Node{
                graph_.origin_node, kOriginName, -1, -1, NodeKind::Origin
            });
        }

        std::vector<uint8_t> has_incoming(graph_.nodes.size(), 0);
        for (const Edge& e : graph_.edges) {
            if (e.deleted || e.type == EdgeType::Org) continue;
            if (e.dst >= 0 && e.dst < static_cast<int>(has_incoming.size())) {
                has_incoming[e.dst] = 1;
            }
        }

        SemanticHelpers h(graph_);
        for (const Node& node : graph_.nodes) {
            if (node.kind == NodeKind::Origin || node.kind == NodeKind::Terminal) continue;
            if (!h.HasOwnerOutgoing(node.id) || has_incoming[node.id]) continue;
            add_edge(graph_.origin_node,
                     node.id,
                     EdgeType::Org,
                     "graph entry");
        }
    }

    struct SemanticCandidateIndex {
        std::vector<int> owner_nodes;
        std::unordered_map<int, std::vector<int>> owner_nodes_by_server;
        std::unordered_map<int, std::unordered_map<std::string, std::vector<int>>> del_by_server_cut;
        std::unordered_map<std::string, std::vector<int>> concrete_by_name;
        std::unordered_map<std::string, std::vector<int>> wildcard_by_parent;
        std::unordered_map<std::string, std::vector<int>> beta_by_suffix;
        std::unordered_map<std::string, std::vector<int>> concrete_desc_by_suffix;
        std::unordered_map<std::string, std::vector<int>> wildcard_desc_by_suffix;
        std::unordered_map<std::string, std::vector<int>> beta_desc_by_suffix;
    };

    void collect_owner_nodes(const SemanticHelpers& h,
                             SemanticCandidateIndex& index) const {
        index.owner_nodes.reserve(graph_.nodes.size());
        for (const Node& n : graph_.nodes) {
            if (!h.HasOwnerOutgoing(n.id)) continue;
            index.owner_nodes.push_back(n.id);
            index.owner_nodes_by_server[n.server].push_back(n.id);
            if (h.IsAlpha(n.id)) continue;

            const std::string& raw = h.symbolic_stripped_name_ref(n.id);
            const std::string& suff = h.suffix_ref(n.id);
            std::unordered_set<std::string> del_cut_keys;
            for (const std::string& anc : ancestor_suffixes_inclusive(suff)) {
                del_cut_keys.insert(anc);
            }
            for (const std::string& anc : ancestor_suffixes_inclusive(raw)) {
                del_cut_keys.insert(anc);
            }
            for (const std::string& key : del_cut_keys) {
                index.del_by_server_cut[n.server][key].push_back(n.id);
            }
            if (h.IsConcrete(n.id)) {
                index.concrete_by_name[n.name].push_back(n.id);
                for (const std::string& anc : ancestor_suffixes_proper(raw)) {
                    index.concrete_desc_by_suffix[anc].push_back(n.id);
                }
            } else if (h.IsWildcard(n.id)) {
                index.wildcard_by_parent[raw].push_back(n.id);
                for (const std::string& anc : ancestor_suffixes_inclusive(raw)) {
                    index.wildcard_desc_by_suffix[anc].push_back(n.id);
                }
            } else if (h.IsBeta(n.id)) {
                index.beta_by_suffix[suff].push_back(n.id);
                for (const std::string& anc : ancestor_suffixes_inclusive(suff)) {
                    index.beta_desc_by_suffix[anc].push_back(n.id);
                }
            }
        }
    }

    void build_del_edges(const Edge& ns_edge,
                         const SemanticHelpers& h,
                         const SemanticCandidateIndex& index,
                         IdMarker& marker,
        SemanticBuildStats* stats) {
        const Node& alpha = graph_.nodes[ns_edge.src];
        const Node& ns_target = graph_.nodes[ns_edge.dst];
        const std::string& cut = h.suffix_ref(alpha.id);
        const Zone& current_zone = graph_.zones[alpha.zone];

        // An apex NS is authoritative data for its own zone.  Only a
        // non-apex NS owner denotes a zone cut and induces Del edges.
        if (cut == current_zone.origin) return;

        auto sit = graph_.server_by_name.find(ns_target.name);
        if (sit == graph_.server_by_name.end()) return;

        int target_server = sit->second;

        auto server_it = index.del_by_server_cut.find(target_server);
        if (server_it == index.del_by_server_cut.end()) return;
        auto owners = server_it->second.find(cut);
        if (owners == server_it->second.end()) return;

        for (int nid : owners->second) {
            if (!marker.mark(nid)) continue;
            if (stats) ++stats->del_candidates_checked;
            if (h.IsAlpha(nid)) continue;
            if (graph_.nodes[nid].zone == alpha.zone) continue;
            const std::string& ns = h.suffix_ref(nid);
            const std::string& raw = h.symbolic_stripped_name_ref(nid);
            // The NS rdata node is the delegation server name.  Do not add
            // a Del edge from that server-name node to an owner with the
            // same name in the child zone; ordinary A/AAAA edges on that
            // owner describe the server address, not a child-query entry.
            if (!h.IsBeta(nid) && raw == ns_target.name) continue;
            bool matches_cut = ns == cut ||
                               is_descendant_or_same(ns, cut) ||
                               is_descendant_or_same(raw, cut);
            if (!matches_cut) continue;
            int added = add_edge(ns_edge.dst, nid, EdgeType::Del,
                                 "induced by " + ns_edge.record, ns_edge.id);
            if (stats && added >= 0) ++stats->del_edges_added;
        }
    }

    static void add_index_candidates(const std::unordered_map<std::string, std::vector<int>>& index,
                                     const std::string& key,
                                     std::vector<int>& candidates,
                                     IdMarker& marker) {
        auto it = index.find(key);
        if (it == index.end()) return;
        for (int nid : it->second) {
            if (marker.mark(nid)) candidates.push_back(nid);
        }
    }

    void build_drew_edges(const Edge& dname_edge,
                          const SemanticHelpers& h,
                          const SemanticCandidateIndex& index,
                          IdMarker& marker,
                          SemanticBuildStats* stats) {
        int source = dname_edge.dst;
        const std::string& source_suffix = h.suffix_ref(source);
        std::vector<int> candidates;

        add_index_candidates(index.beta_desc_by_suffix, source_suffix, candidates, marker);
        for (const std::string& anc : ancestor_suffixes_inclusive(source_suffix)) {
            add_index_candidates(index.beta_by_suffix, anc, candidates, marker);
        }
        add_index_candidates(index.concrete_desc_by_suffix, source_suffix, candidates, marker);
        add_index_candidates(index.wildcard_desc_by_suffix, source_suffix, candidates, marker);

        for (int nid : candidates) {
            if (stats) ++stats->drew_candidates_checked;
            if (h.IsAlpha(nid)) continue;

            bool ok = false;
            if (h.IsBeta(nid)) {
                ok = h.betaTargetCompatible(source, nid);
            } else if (h.IsConcrete(nid) || h.IsWildcard(nid)) {
                ok = h.dnameTargetNameMatches(source, nid);
            }

            if (!ok) continue;
            int added = add_edge(source, nid, EdgeType::DRew,
                                 "induced by " + dname_edge.record, dname_edge.id);
            if (stats && added >= 0) ++stats->drew_edges_added;
        }
    }

    void build_crew_edges(const Edge& cname_edge,
                          const SemanticHelpers& h,
                          const SemanticCandidateIndex& index,
                          IdMarker& marker,
                          SemanticBuildStats* stats) {
        int source = cname_edge.dst;
        const Node& source_node = graph_.nodes[source];
        const std::string& raw = h.symbolic_stripped_name_ref(source);
        std::vector<int> candidates;

        add_index_candidates(index.concrete_by_name, source_node.name, candidates, marker);
        if (auto parent = immediate_parent_suffix(raw)) {
            add_index_candidates(index.wildcard_by_parent, *parent, candidates, marker);
        }
        std::vector<std::string> beta_suffixes =
            h.IsBeta(source) ? ancestor_suffixes_inclusive(raw)
                             : ancestor_suffixes_proper(raw);
        for (const std::string& anc : beta_suffixes) {
            add_index_candidates(index.beta_by_suffix, anc, candidates, marker);
        }

        for (int nid : candidates) {
            if (stats) ++stats->crew_candidates_checked;
            // In the same server+zone a CNAME rdata node and the matching
            // owner node are the same unique node.  Its ordinary A/AAAA/MX/
            // TXT edges already continue the path, so a CRew self-loop is
            // not a real rewrite candidate.
            if (nid == source) continue;
            if (h.IsAlpha(nid)) continue;

            bool ok = false;
            if (h.IsBeta(nid)) {
                ok = h.betaMatches(nid, source);
            } else if (h.IsConcrete(nid)) {
                ok = graph_.nodes[nid].name == graph_.nodes[source].name;
            } else if (h.IsWildcard(nid)) {
                ok = h.wildcardCovers(nid, source);
            }

            if (!ok) continue;
            int added = add_edge(source, nid, EdgeType::CRew,
                                 "induced by " + cname_edge.record, cname_edge.id);
            if (stats && added >= 0) ++stats->crew_edges_added;
        }
    }
};

class ReachComputer {
public:
    explicit ReachComputer(SemanticGraph& graph) : graph_(graph), helpers_(graph) {
        owner_outgoing_.assign(graph_.nodes.size(), 0);
        active_base_edges_by_zone_.assign(graph_.zones.size(), 0);
        for (const Edge& e : graph_.edges) {
            if (e.deleted) continue;
            if (is_base_type(e.type) &&
                e.src >= 0 &&
                e.src < static_cast<int>(owner_outgoing_.size())) {
                ++owner_outgoing_[e.src];
                adjustZoneActivity(e, 1);
            }
            if (e.type == EdgeType::NS) adjustNsFacts(e, 1);
        }
        owner_node_indexed_.assign(graph_.nodes.size(), 0);
        for (const Node& n : graph_.nodes) {
            if (!HasOwnerOutgoingCached(n.id)) continue;
            activateOwnerNode(n.id);
        }
    }

    void ComputeReach() {
        for (Edge& e : graph_.edges) {
            e.reach = ComputeEdgeReach(e);
        }
    }

    void OnBaseEdgeActivated(const Edge& e) {
        if (!is_base_type(e.type) || e.src < 0) return;
        ensureNodeCapacity(e.src);
        adjustZoneActivity(e, 1);
        const uint32_t previous = owner_outgoing_[e.src]++;
        if (previous == 0) activateOwnerNode(e.src);
        if (e.type == EdgeType::NS) adjustNsFacts(e, 1);
    }

    void OnBaseEdgeDeactivated(const Edge& e) {
        if (!is_base_type(e.type) || e.src < 0 ||
            e.src >= static_cast<int>(owner_outgoing_.size()) ||
            owner_outgoing_[e.src] == 0) {
            return;
        }
        if (e.type == EdgeType::NS) adjustNsFacts(e, -1);
        adjustZoneActivity(e, -1);
        --owner_outgoing_[e.src];
        if (owner_outgoing_[e.src] == 0) deactivateOwnerNode(e.src);
    }

    bool HasOwnerOutgoing(int node) const {
        return HasOwnerOutgoingCached(node);
    }

    bool IsZoneActive(int zone) const {
        return zone >= 0 &&
               zone < static_cast<int>(active_base_edges_by_zone_.size()) &&
               active_base_edges_by_zone_[zone] != 0;
    }

    int ComputeEdgeReach(const Edge& e) const {
        if (e.deleted) {
            return 0;
        } else if (e.forced_unreachable) {
            return 0;
        } else if (is_base_type(e.type)) {
            return 1;
        } else if (!HasOwnerOutgoingCached(e.dst)) {
            return 0;
        } else if (e.type == EdgeType::Org) {
            return ComputeOrgReach(e);
        } else if (IsDelegationShadowedCached(e.dst)) {
            return 0;
        } else if (e.type == EdgeType::Del) {
            return ComputeDelReach(e);
        } else if (e.type == EdgeType::DRew) {
            return ComputeDRewReach(e);
        } else if (e.type == EdgeType::CRew) {
            return ComputeCRewReach(e);
        }
        return 0;
    }

private:
    using NameCounts = std::unordered_map<std::string, uint32_t>;

    SemanticGraph& graph_;
    SemanticHelpers helpers_;
    std::vector<uint32_t> owner_outgoing_;
    std::vector<uint8_t> owner_node_indexed_;
    std::vector<uint32_t> active_base_edges_by_zone_;
    std::unordered_map<int, NameCounts> nonalpha_owner_names_by_server_;
    std::unordered_map<int, NameCounts> wildcard_parent_names_by_server_;
    std::unordered_map<int, NameCounts> concrete_owner_names_by_server_;
    std::unordered_map<int, NameCounts> concrete_parent_names_by_server_;
    std::unordered_map<uint64_t, NameCounts> nonalpha_owner_names_by_context_;
    std::unordered_map<uint64_t, NameCounts> wildcard_parent_names_by_context_;
    std::unordered_map<uint64_t, NameCounts> concrete_owner_names_by_context_;
    std::unordered_map<int, std::vector<int>> beta_nodes_by_server_;
    std::unordered_map<uint64_t, std::vector<int>> beta_nodes_by_server_zone_;
    std::unordered_map<uint64_t, std::vector<int>> symbolic_priority_nodes_by_server_zone_;
    std::unordered_map<int, NameCounts> active_zone_origins_by_server_;
    NameCounts active_zone_origins_;
    std::unordered_map<int, NameCounts> ns_cuts_by_zone_;
    std::unordered_map<int, NameCounts> local_ns_cuts_by_zone_;
    std::unordered_map<int, NameCounts> glue_names_by_zone_;

    static uint64_t serverZoneKey(int server, int zone) {
        return (static_cast<uint64_t>(static_cast<uint32_t>(server)) << 32) |
               static_cast<uint32_t>(zone);
    }

    static void adjustNameCount(NameCounts& counts,
                                const std::string& name,
                                int delta) {
        if (delta > 0) {
            counts[name] += static_cast<uint32_t>(delta);
            return;
        }
        auto it = counts.find(name);
        if (it == counts.end()) return;
        const uint32_t amount = static_cast<uint32_t>(-delta);
        if (it->second <= amount) {
            counts.erase(it);
        } else {
            it->second -= amount;
        }
    }

    static bool hasName(const std::unordered_map<int, NameCounts>& index,
                        int key,
                        const std::string& name) {
        auto outer = index.find(key);
        if (outer == index.end()) return false;
        auto inner = outer->second.find(name);
        return inner != outer->second.end() && inner->second != 0;
    }

    static bool hasContextName(
        const std::unordered_map<uint64_t, NameCounts>& index,
        uint64_t key,
        const std::string& name) {
        auto outer = index.find(key);
        if (outer == index.end()) return false;
        auto inner = outer->second.find(name);
        return inner != outer->second.end() && inner->second != 0;
    }

    void ensureNodeCapacity(int node) {
        if (node < 0) return;
        const size_t need = static_cast<size_t>(node) + 1;
        if (owner_outgoing_.size() < need) owner_outgoing_.resize(need, 0);
        if (owner_node_indexed_.size() < need) owner_node_indexed_.resize(need, 0);
    }

    void ensureZoneCapacity(int zone) {
        if (zone < 0) return;
        const size_t need = static_cast<size_t>(zone) + 1;
        if (active_base_edges_by_zone_.size() < need) {
            active_base_edges_by_zone_.resize(need, 0);
        }
    }

    void adjustZoneActivity(const Edge& e, int delta) {
        if (!is_base_type(e.type) ||
            e.src < 0 || e.src >= static_cast<int>(graph_.nodes.size())) {
            return;
        }
        const int zone = graph_.nodes[e.src].zone;
        if (zone < 0 || zone >= static_cast<int>(graph_.zones.size())) return;
        ensureZoneCapacity(zone);

        uint32_t& count = active_base_edges_by_zone_[zone];
        const bool was_active = count != 0;
        if (delta > 0) {
            count += static_cast<uint32_t>(delta);
        } else {
            const uint32_t amount = static_cast<uint32_t>(-delta);
            count = count > amount ? count - amount : 0;
        }
        const bool is_active = count != 0;
        if (was_active == is_active) return;

        const Zone& z = graph_.zones[zone];
        const int direction = is_active ? 1 : -1;
        adjustNameCount(active_zone_origins_by_server_[z.server],
                        z.origin,
                        direction);
        adjustNameCount(active_zone_origins_, z.origin, direction);
    }

    static std::optional<std::string> bestMatchingOrigin(
        const NameCounts& origins,
        const std::string& name) {
        for (const std::string& suffix : ancestor_suffixes_inclusive(name)) {
            auto it = origins.find(suffix);
            if (it != origins.end() && it->second != 0) return suffix;
        }
        return std::nullopt;
    }

    bool IsBestZoneOnServer(int zone,
                            int server,
                            const std::string& query_name) const {
        if (!IsZoneActive(zone) ||
            zone < 0 || zone >= static_cast<int>(graph_.zones.size())) {
            return false;
        }
        auto it = active_zone_origins_by_server_.find(server);
        if (it == active_zone_origins_by_server_.end()) return false;
        const auto best = bestMatchingOrigin(it->second, query_name);
        return best.has_value() && graph_.zones[zone].origin == *best;
    }

    bool IsBestKnownZone(int zone, const std::string& query_name) const {
        if (!IsZoneActive(zone) ||
            zone < 0 || zone >= static_cast<int>(graph_.zones.size())) {
            return false;
        }
        const auto best = bestMatchingOrigin(active_zone_origins_, query_name);
        return best.has_value() && graph_.zones[zone].origin == *best;
    }

    void activateOwnerNode(int node) {
        ensureNodeCapacity(node);
        const Node& n = graph_.nodes[node];
        const uint64_t context = serverZoneKey(n.server, n.zone);
        if (!helpers_.IsAlpha(node)) {
            adjustNameCount(nonalpha_owner_names_by_server_[n.server], n.name, 1);
            adjustNameCount(nonalpha_owner_names_by_context_[context], n.name, 1);
            if (n.kind == NodeKind::Wildcard) {
                adjustNameCount(
                    wildcard_parent_names_by_server_[n.server],
                    helpers_.symbolic_stripped_name_ref(node),
                    1);
                adjustNameCount(
                    wildcard_parent_names_by_context_[context],
                    helpers_.symbolic_stripped_name_ref(node),
                    1);
            }
        }
        if (n.kind == NodeKind::Concrete) {
            adjustNameCount(concrete_owner_names_by_server_[n.server], n.name, 1);
            adjustNameCount(concrete_owner_names_by_context_[context], n.name, 1);
            if (auto parent = immediate_parent_suffix(
                    helpers_.symbolic_stripped_name_ref(node))) {
                adjustNameCount(concrete_parent_names_by_server_[n.server], *parent, 1);
            }
        }

        if (owner_node_indexed_[node]) return;
        owner_node_indexed_[node] = 1;
        if (n.kind == NodeKind::Alpha || n.kind == NodeKind::Beta) {
            symbolic_priority_nodes_by_server_zone_[
                serverZoneKey(n.server, n.zone)].push_back(node);
        }
        if (n.kind == NodeKind::Beta) {
            beta_nodes_by_server_[n.server].push_back(node);
            beta_nodes_by_server_zone_[serverZoneKey(n.server, n.zone)].push_back(node);
        }
    }

    void deactivateOwnerNode(int node) {
        if (node < 0 || node >= static_cast<int>(graph_.nodes.size())) return;
        const Node& n = graph_.nodes[node];
        const uint64_t context = serverZoneKey(n.server, n.zone);
        if (!helpers_.IsAlpha(node)) {
            adjustNameCount(nonalpha_owner_names_by_server_[n.server], n.name, -1);
            adjustNameCount(nonalpha_owner_names_by_context_[context], n.name, -1);
            if (n.kind == NodeKind::Wildcard) {
                adjustNameCount(
                    wildcard_parent_names_by_server_[n.server],
                    helpers_.symbolic_stripped_name_ref(node),
                    -1);
                adjustNameCount(
                    wildcard_parent_names_by_context_[context],
                    helpers_.symbolic_stripped_name_ref(node),
                    -1);
            }
        }
        if (n.kind == NodeKind::Concrete) {
            adjustNameCount(concrete_owner_names_by_server_[n.server], n.name, -1);
            adjustNameCount(concrete_owner_names_by_context_[context], n.name, -1);
            if (auto parent = immediate_parent_suffix(
                    helpers_.symbolic_stripped_name_ref(node))) {
                adjustNameCount(concrete_parent_names_by_server_[n.server], *parent, -1);
            }
        }
    }

    void adjustNsFacts(const Edge& e, int delta) {
        if (e.type != EdgeType::NS ||
            e.src < 0 || e.src >= static_cast<int>(graph_.nodes.size()) ||
            e.dst < 0 || e.dst >= static_cast<int>(graph_.nodes.size())) {
            return;
        }
        const Node& owner = graph_.nodes[e.src];
        if (owner.zone < 0 || owner.zone >= static_cast<int>(graph_.zones.size())) return;
        const Zone& zone = graph_.zones[owner.zone];
        const std::string& cut = helpers_.suffix_ref(owner.id);
        if (cut == zone.origin) return;

        adjustNameCount(ns_cuts_by_zone_[owner.zone], cut, delta);
        const std::string& ns_target = graph_.nodes[e.dst].name;
        auto sit = graph_.server_by_name.find(ns_target);
        if (ns_target == graph_.servers[zone.server].name ||
            (sit != graph_.server_by_name.end() && sit->second == zone.server)) {
            adjustNameCount(local_ns_cuts_by_zone_[owner.zone], cut, delta);
        }
        if (is_descendant_or_same(ns_target, zone.origin)) {
            adjustNameCount(glue_names_by_zone_[owner.zone], ns_target, delta);
        }
    }

    bool HasOwnerOutgoingCached(int node) const {
        return node >= 0 &&
               node < static_cast<int>(owner_outgoing_.size()) &&
               owner_outgoing_[node] != 0;
    }

    bool ExistsConcreteOwnerNamedCached(int server,
                                        int zone,
                                        const std::string& name) const {
        return hasContextName(concrete_owner_names_by_context_,
                              serverZoneKey(server, zone),
                              name);
    }

    bool ExistsBetaWithSameSuffixCached(int server, int zone, int v) const {
        auto it = beta_nodes_by_server_zone_.find(serverZoneKey(server, zone));
        if (it == beta_nodes_by_server_zone_.end()) return false;
        for (int beta : it->second) {
            if (beta == v) continue;
            if (!HasOwnerOutgoingCached(beta)) continue;
            if (helpers_.sameSuffix(beta, v)) return true;
        }
        return false;
    }

    bool ExistsBetaLocalCoverCached(int server, int zone, int v) const {
        auto it = beta_nodes_by_server_zone_.find(serverZoneKey(server, zone));
        if (it == beta_nodes_by_server_zone_.end()) return false;
        for (int beta : it->second) {
            if (!HasOwnerOutgoingCached(beta)) continue;
            if (helpers_.sameSuffix(beta, v)) return true;
        }
        return false;
    }

    bool ExistsLocalCoverForNameCached(int server,
                                       int zone,
                                       const std::string& query_name) const {
        const uint64_t context = serverZoneKey(server, zone);
        if (hasContextName(nonalpha_owner_names_by_context_,
                           context,
                           query_name)) {
            return true;
        }

        auto parent = immediate_parent_suffix(query_name);
        if (parent.has_value() &&
            hasContextName(wildcard_parent_names_by_context_,
                           context,
                           *parent)) {
            return true;
        }

        auto it = beta_nodes_by_server_zone_.find(context);
        if (it == beta_nodes_by_server_zone_.end()) return false;
        for (int beta : it->second) {
            if (!HasOwnerOutgoingCached(beta)) continue;
            if (is_strict_descendant_of(query_name, helpers_.suffix_ref(beta))) {
                return true;
            }
        }
        return false;
    }

    bool ExistsNonAlphaLocalCoverCached(int server, int zone, int v) const {
        const uint64_t context = serverZoneKey(server, zone);
        const std::string& target_name = graph_.nodes[v].name;
        if (hasContextName(nonalpha_owner_names_by_context_,
                           context,
                           target_name)) {
            return true;
        }

        const std::string& raw = helpers_.symbolic_stripped_name_ref(v);
        auto parent = immediate_parent_suffix(raw);
        if (parent.has_value() &&
            hasContextName(wildcard_parent_names_by_context_,
                           context,
                           *parent)) {
            return true;
        }
        return ExistsBetaLocalCoverCached(server, zone, v);
    }

    bool IsDelegationShadowedCached(int node) const {
        if (node < 0 || node >= static_cast<int>(graph_.nodes.size())) return false;
        if (helpers_.IsAlpha(node)) return false;

        const Node& n = graph_.nodes[node];
        auto cuts_it = ns_cuts_by_zone_.find(n.zone);
        if (cuts_it == ns_cuts_by_zone_.end()) return false;

        const std::string& owner_name = helpers_.symbolic_stripped_name_ref(node);
        if (hasName(glue_names_by_zone_, n.zone, owner_name)) {
            return false;
        }

        for (const auto& [cut, count] : cuts_it->second) {
            if (count == 0 || hasName(local_ns_cuts_by_zone_, n.zone, cut)) continue;
            if (is_strict_descendant_of(owner_name, cut)) return true;
        }
        return false;
    }

    int ComputeOrgReach(const Edge& e) const {
        const int t = e.dst;
        if (helpers_.IsAlpha(t) || helpers_.IsBeta(t)) return 1;

        const Node& target = graph_.nodes[t];
        const std::string& target_name = helpers_.symbolic_stripped_name_ref(t);
        if (hasName(glue_names_by_zone_, target.zone, target_name)) {
            return 1;
        }

        auto it = symbolic_priority_nodes_by_server_zone_.find(
            serverZoneKey(target.server, target.zone));
        if (it == symbolic_priority_nodes_by_server_zone_.end()) return 1;

        for (int symbolic : it->second) {
            if (!HasOwnerOutgoingCached(symbolic)) continue;
            const Node& candidate = graph_.nodes[symbolic];
            const std::string& suffix = helpers_.suffix_ref(symbolic);
            if (candidate.kind == NodeKind::Alpha) {
                // Apex NS records coexist with other apex RRsets.  A non-apex
                // alpha is a delegation cut and has the same entry priority as
                // beta when it covers a root candidate.
                if (suffix == graph_.zones[candidate.zone].origin) continue;
                if (is_descendant_or_same(target_name, suffix)) return 0;
            } else if (candidate.kind == NodeKind::Beta) {
                // DNAME applies below, but not at, its owner name.
                if (is_strict_descendant_of(target_name, suffix)) return 0;
            }
        }
        return 1;
    }

    int ComputeDelReach(const Edge& e) const {
        int t = e.dst;
        const Node& tn = graph_.nodes[t];
        const std::string query_name =
            helpers_.symbolic_stripped_name_ref(t);
        // A delegated server answers from the most-specific zone it hosts
        // for the represented query, not from every matching zone file.
        if (!IsBestZoneOnServer(tn.zone, tn.server, query_name)) {
            return 0;
        }
        if (helpers_.IsBeta(t)) {
            return 1;
        } else if (ExistsBetaWithSameSuffixCached(tn.server, tn.zone, t)) {
            return 0;
        } else {
            return 1;
        }
    }

    int ComputeDRewReach(const Edge& e) const {
        int s = e.src;
        int t = e.dst;
        const Node& sn = graph_.nodes[s];
        const Node& tn = graph_.nodes[t];
        int Ss = sn.server;
        int St = tn.server;
        const bool same_context = Ss == St && sn.zone == tn.zone;

        // A rewrite remains in its exact source zone when that zone covers
        // the candidate.  Otherwise it enters the most-specific known zone.
        if (same_context) {
            if (helpers_.IsBeta(t)) {
                return 1;
            } else if (ExistsBetaWithSameSuffixCached(Ss, tn.zone, t)) {
                return 0;
            } else {
                return 1;
            }
        } else {
            if (ExistsNonAlphaLocalCoverCached(Ss, sn.zone, t)) {
                return 0;
            }
            const std::string query_name =
                helpers_.symbolic_stripped_name_ref(t);
            if (!IsBestKnownZone(tn.zone, query_name)) {
                return 0;
            }
            if (helpers_.IsBeta(t)) {
                return 1;
            } else if (ExistsBetaWithSameSuffixCached(St, tn.zone, t)) {
                return 0;
            } else {
                return 1;
            }
        }
    }

    int ComputeCRewReach(const Edge& e) const {
        int s = e.src;
        int t = e.dst;
        const Node& sn = graph_.nodes[s];
        const Node& tn = graph_.nodes[t];
        int Ss = sn.server;
        int St = tn.server;
        const std::string query_name =
            helpers_.symbolic_stripped_name_ref(s);
        const bool same_context = Ss == St && sn.zone == tn.zone;

        // "Local" means the same zone file, not merely another zone hosted
        // by the same nameserver.
        if (same_context) {
            if (helpers_.IsBeta(t)) {
                return 1;
            } else if (ExistsBetaWithSameSuffixCached(Ss, tn.zone, t)) {
                return 0;
            } else if (helpers_.IsConcrete(t)) {
                return 1;
            } else if (helpers_.IsWildcard(t) &&
                       ExistsConcreteOwnerNamedCached(
                           Ss, tn.zone, query_name)) {
                return 0;
            } else {
                return 1;
            }
        } else {
            if (ExistsLocalCoverForNameCached(Ss, sn.zone, query_name)) {
                return 0;
            }
            if (!IsBestKnownZone(tn.zone, query_name)) {
                return 0;
            }
            if (helpers_.IsBeta(t)) {
                return 1;
            } else if (ExistsBetaWithSameSuffixCached(St, tn.zone, t)) {
                return 0;
            } else if (helpers_.IsConcrete(t)) {
                return 1;
            } else if (helpers_.IsWildcard(t) &&
                       ExistsConcreteOwnerNamedCached(
                           St, tn.zone, query_name)) {
                return 0;
            } else {
                return 1;
            }
        }
    }
};

static std::vector<int> collect_reachable_entry_nodes(const SemanticGraph& graph) {
    std::vector<int> entries;
    if (graph.origin_node >= 0 &&
        graph.origin_node < static_cast<int>(graph.nodes.size())) {
        auto it = graph.outgoing_edges.find(graph.origin_node);
        if (it != graph.outgoing_edges.end()) {
            entries.reserve(it->second.size());
            for (int eid : it->second) {
                if (eid < 0 || eid >= static_cast<int>(graph.edges.size())) continue;
                const Edge& e = graph.edges[eid];
                if (!e.deleted && e.type == EdgeType::Org && e.reach == 1) {
                    entries.push_back(e.dst);
                }
            }
        }
    }

    // Compatibility fallback for graphs constructed before Origin was added.
    if (entries.empty() && graph.origin_node < 0) {
        for (const Node& node : graph.nodes) {
            if (node.kind == NodeKind::Alpha) entries.push_back(node.id);
        }
    }
    return entries;
}

struct RewriteEvent {
    int edge = -1;
    size_t prefix_len = 0;
    std::string before_q;
    std::string after_q;
};

struct PathResult {
    int start_alpha = -1;
    int final_node = -1;
    std::string final_result;
    std::vector<int> edges;
    std::map<std::string, std::string> bindings;
    std::string reason;
    bool has_query_rewrite = false;
    std::string final_query;
    std::string rewrite_start_name;
    std::vector<RewriteEvent> rewrite_events;
};

struct VisitKey {
    int node = -1;
    std::string q;
    bool require_base_next = false;
    bool has_alpha = false;
    bool has_beta = false;
    std::string alpha;
    std::string beta;

    bool operator==(const VisitKey& other) const {
        return node == other.node &&
               q == other.q &&
               require_base_next == other.require_base_next &&
               has_alpha == other.has_alpha &&
               has_beta == other.has_beta &&
               alpha == other.alpha &&
               beta == other.beta;
    }
};

struct VisitKeyHash {
    size_t operator()(const VisitKey& k) const {
        size_t h = std::hash<int>{}(k.node);
        hash_combine_value(h, std::hash<std::string>{}(k.q));
        hash_combine_value(h, std::hash<bool>{}(k.require_base_next));
        hash_combine_value(h, std::hash<bool>{}(k.has_alpha));
        hash_combine_value(h, std::hash<bool>{}(k.has_beta));
        if (k.has_alpha) hash_combine_value(h, std::hash<std::string>{}(k.alpha));
        if (k.has_beta) hash_combine_value(h, std::hash<std::string>{}(k.beta));
        return h;
    }
};

struct EmittedPathKey {
    int start_alpha = -1;
    int final_node = -1;
    std::string reason;
    std::string q;
    bool require_base_next = false;
    std::vector<int> edges;
    bool has_alpha = false;
    bool has_beta = false;
    std::string alpha;
    std::string beta;

    bool operator==(const EmittedPathKey& other) const {
        return start_alpha == other.start_alpha &&
               final_node == other.final_node &&
               reason == other.reason &&
               q == other.q &&
               require_base_next == other.require_base_next &&
               edges == other.edges &&
               has_alpha == other.has_alpha &&
               has_beta == other.has_beta &&
               alpha == other.alpha &&
               beta == other.beta;
    }
};

struct EmittedPathKeyHash {
    size_t operator()(const EmittedPathKey& k) const {
        size_t h = std::hash<int>{}(k.start_alpha);
        hash_combine_value(h, std::hash<int>{}(k.final_node));
        hash_combine_value(h, std::hash<std::string>{}(k.reason));
        hash_combine_value(h, std::hash<std::string>{}(k.q));
        hash_combine_value(h, std::hash<bool>{}(k.require_base_next));
        for (int eid : k.edges) {
            hash_combine_value(h, std::hash<int>{}(eid));
        }
        hash_combine_value(h, std::hash<bool>{}(k.has_alpha));
        hash_combine_value(h, std::hash<bool>{}(k.has_beta));
        if (k.has_alpha) hash_combine_value(h, std::hash<std::string>{}(k.alpha));
        if (k.has_beta) hash_combine_value(h, std::hash<std::string>{}(k.beta));
        return h;
    }
};

class EmittedPathSet {
public:
    void reserve(size_t n) {
        if (n > kPromoteThreshold) {
            large_.reserve(n);
        } else {
            small_.reserve(n);
        }
    }

    bool insert(EmittedPathKey&& key) {
        if (!promoted_) {
            if (std::find(small_.begin(), small_.end(), key) != small_.end()) {
                return false;
            }
            if (small_.size() < kPromoteThreshold) {
                small_.push_back(std::move(key));
                return true;
            }
            promote();
        }
        return large_.insert(std::move(key)).second;
    }

private:
    static constexpr size_t kPromoteThreshold = 128;
    bool promoted_ = false;
    std::vector<EmittedPathKey> small_;
    std::unordered_set<EmittedPathKey, EmittedPathKeyHash> large_;

    void promote() {
        if (promoted_) return;
        large_.reserve(small_.size() * 2 + 1);
        for (auto& key : small_) {
            large_.insert(std::move(key));
        }
        small_.clear();
        small_.shrink_to_fit();
        promoted_ = true;
    }
};

struct TraversalState {
    int node = -1;
    std::string q;
    bool has_alpha = false;
    bool has_beta = false;
    std::string alpha_binding;
    std::string beta_binding;
    std::vector<int> path;
    // DFS depth is capped at a small constant (24).  A vector avoids hashing
    // several strings at every step while preserving the exact same visited
    // state semantics.
    std::vector<VisitKey> seen;
    bool require_base_next = false;
    bool has_query_rewrite = false;
    std::string rewrite_start_name;
    std::vector<RewriteEvent> rewrite_events;
};

struct PathView {
    int start_alpha = -1;
    int final_node = -1;
    const std::vector<int>* edges = nullptr;
    bool has_query_rewrite = false;
    const std::string* final_query = nullptr;
    const std::string* rewrite_start_name = nullptr;
    const std::vector<RewriteEvent>* rewrite_events = nullptr;
};

class PathTraverser {
public:
    using PathObserver = std::function<void(const PathResult&)>;
    using PathViewObserver = std::function<void(const PathView&)>;

    explicit PathTraverser(const SemanticGraph& graph)
        : graph_(graph),
          helpers_(graph),
          outgoing_by_node_(graph.nodes.size(), nullptr) {
        for (const auto& kv : graph_.outgoing_edges) {
            if (kv.first >= 0 && kv.first < static_cast<int>(outgoing_by_node_.size())) {
                outgoing_by_node_[kv.first] = &kv.second;
            }
        }
    }

    std::vector<PathResult> traverseAll(size_t max_depth = 24) const {
        return traverseAll(max_depth, nullptr);
    }

    std::vector<PathResult> traverseAll(
        size_t max_depth,
        const PathObserver& observer) const {
        std::vector<PathResult> out;
        out.reserve(graph_.edges.size());
        EmittedPathSet emitted_paths;
        emitted_paths.reserve(graph_.edges.size());
        for (int start : collect_reachable_entry_nodes(graph_)) {
            TraversalState st;
            st.node = start;
            st.q = initial_query(start);
            st.path.reserve(max_depth);
            st.seen.reserve(max_depth + 1);
            st.rewrite_events.reserve(max_depth);
            bind_symbol_if_needed(st, start);
            size_t emitted_count = 0;
            dfs(start, st, start, max_depth, out, emitted_paths, observer, nullptr, true, emitted_count);
        }
        return out;
    }

    std::vector<PathResult> traverseFromNode(int start, size_t max_depth = 24) const {
        return traverseFromNode(start, max_depth, nullptr);
    }

    std::vector<PathResult> traverseFromNode(
        int start,
        size_t max_depth,
        const PathObserver& observer) const {
        std::vector<PathResult> out;
        out.reserve(64);
        EmittedPathSet emitted_paths;
        emitted_paths.reserve(64);
        if (start < 0 || start >= static_cast<int>(graph_.nodes.size())) return out;
        if (graph_.nodes[start].kind == NodeKind::Terminal) return out;

        TraversalState st;
        st.node = start;
        st.q = initial_query(start);
        st.path.reserve(max_depth);
        st.seen.reserve(max_depth + 1);
        st.rewrite_events.reserve(max_depth);
        bind_symbol_if_needed(st, start);
        size_t emitted_count = 0;
        dfs(start, st, start, max_depth, out, emitted_paths, observer, nullptr, true, emitted_count);
        return out;
    }

    std::vector<PathResult> traverseFromAlpha(
        int alpha,
        size_t max_depth,
        const PathObserver& observer) const {
        std::vector<PathResult> out;
        out.reserve(64);
        EmittedPathSet emitted_paths;
        emitted_paths.reserve(64);
        if (alpha < 0 || alpha >= static_cast<int>(graph_.nodes.size())) return out;
        if (!helpers_.IsAlpha(alpha)) return out;

        TraversalState st;
        st.node = alpha;
        st.q = helpers_.suffix(alpha);
        st.path.reserve(max_depth);
        st.seen.reserve(max_depth + 1);
        st.rewrite_events.reserve(max_depth);
        bind_symbol_if_needed(st, alpha);
        size_t emitted_count = 0;
        dfs(alpha, st, alpha, max_depth, out, emitted_paths, observer, nullptr, true, emitted_count);
        return out;
    }

    size_t traverseFromAlphaStreaming(
        int alpha,
        size_t max_depth,
        const PathViewObserver& observer) const {
        std::vector<PathResult> unused;
        EmittedPathSet emitted_paths;
        emitted_paths.reserve(64);
        if (alpha < 0 || alpha >= static_cast<int>(graph_.nodes.size())) return 0;
        if (!helpers_.IsAlpha(alpha)) return 0;

        TraversalState st;
        st.node = alpha;
        st.q = helpers_.suffix(alpha);
        st.path.reserve(max_depth);
        st.seen.reserve(max_depth + 1);
        st.rewrite_events.reserve(max_depth);
        bind_symbol_if_needed(st, alpha);
        size_t emitted_count = 0;
        dfs(alpha, st, alpha, max_depth, unused, emitted_paths, nullptr, observer, false, emitted_count);
        return emitted_count;
    }

    size_t traverseFromNodeStreaming(
        int start,
        size_t max_depth,
        const PathViewObserver& observer) const {
        std::vector<PathResult> unused;
        EmittedPathSet emitted_paths;
        emitted_paths.reserve(64);
        if (start < 0 || start >= static_cast<int>(graph_.nodes.size())) return 0;
        if (graph_.nodes[start].kind == NodeKind::Terminal) return 0;

        TraversalState st;
        st.node = start;
        st.q = initial_query(start);
        st.path.reserve(max_depth);
        st.seen.reserve(max_depth + 1);
        st.rewrite_events.reserve(max_depth);
        bind_symbol_if_needed(st, start);
        size_t emitted_count = 0;
        dfs(start, st, start, max_depth, unused, emitted_paths, nullptr, observer, false, emitted_count);
        return emitted_count;
    }

private:
    const SemanticGraph& graph_;
    SemanticHelpers helpers_;
    std::vector<const std::vector<int>*> outgoing_by_node_;

    static bool requires_immediate_origin(EdgeType type) {
        return type == EdgeType::Del ||
               type == EdgeType::DRew ||
               type == EdgeType::CRew;
    }

    bool follows_inducing_record(const Edge& edge,
                                 const TraversalState& state) const {
        if (!requires_immediate_origin(edge.type)) return true;
        auto origin = graph_.semantic_edge_origin.find(edge.id);
        return origin != graph_.semantic_edge_origin.end() &&
               !state.path.empty() &&
               state.path.back() == origin->second;
    }

    std::string initial_query(int node) const {
        if (node < 0 || node >= static_cast<int>(graph_.nodes.size())) return "";
        if (helpers_.IsBeta(node)) return "_." + helpers_.suffix_ref(node);
        return helpers_.symbolic_stripped_name_ref(node);
    }

    void dfs(int start_alpha,
             TraversalState& st,
             int current,
             size_t max_depth,
             std::vector<PathResult>& out,
             EmittedPathSet& emitted_paths,
             const PathObserver& observer,
             const PathViewObserver& view_observer,
             bool store_results,
             size_t& emitted_count) const {
        const int old_node = st.node;
        const bool old_has_alpha = st.has_alpha;
        const bool old_has_beta = st.has_beta;
        const std::string old_alpha_binding = st.alpha_binding;
        const std::string old_beta_binding = st.beta_binding;
        st.node = current;
        VisitKey sig{current,
                     st.q,
                     st.require_base_next,
                     st.has_alpha,
                     st.has_beta,
                     st.has_alpha ? st.alpha_binding : std::string{},
                     st.has_beta ? st.beta_binding : std::string{}};
        if (std::find(st.seen.begin(), st.seen.end(), sig) != st.seen.end()) {
            emit(start_alpha, current, st, "loop detected", out, emitted_paths, observer, view_observer, store_results, emitted_count);
            st.node = old_node;
            st.has_alpha = old_has_alpha;
            st.has_beta = old_has_beta;
            st.alpha_binding = old_alpha_binding;
            st.beta_binding = old_beta_binding;
            return;
        }
        st.seen.push_back(std::move(sig));

        auto cleanup = [&]() {
            st.seen.pop_back();
            st.node = old_node;
            st.has_alpha = old_has_alpha;
            st.has_beta = old_has_beta;
            st.alpha_binding = old_alpha_binding;
            st.beta_binding = old_beta_binding;
        };

        if (bind_symbol_if_needed(st, current) == false) {
            emit(start_alpha, current, st, "symbol binding conflict", out, emitted_paths, observer, view_observer, store_results, emitted_count);
            cleanup();
            return;
        }

        if (graph_.nodes[current].kind == NodeKind::Terminal) {
            emit(start_alpha, current, st, "terminal", out, emitted_paths, observer, view_observer, store_results, emitted_count);
            cleanup();
            return;
        }

        if (st.path.size() >= max_depth) {
            emit(start_alpha, current, st, "max depth reached", out, emitted_paths, observer, view_observer, store_results, emitted_count);
            cleanup();
            return;
        }

        const std::vector<int>* outgoing_edges =
            (current >= 0 && current < static_cast<int>(outgoing_by_node_.size()))
                ? outgoing_by_node_[current]
                : nullptr;
        if (outgoing_edges == nullptr) {
            emit(start_alpha, current, st, "no reachable outgoing edge", out, emitted_paths, observer, view_observer, store_results, emitted_count);
            cleanup();
            return;
        }

        bool advanced = false;
        bool skipped_semantic_after_semantic = false;
        for (int eid : *outgoing_edges) {
            const Edge& e = graph_.edges[eid];
            if (e.deleted) continue;
            if (e.reach != 1) continue;

            // The destination of an NS RR is a nameserver identity, not the
            // current query owner.  From that node the delegation can enter
            // the child view through Del, or consume A/AAAA glue.  Reusing a
            // same-named CNAME/DNAME owner here would rewrite the delegated
            // query itself and can manufacture a one-edge rewrite loop.
            if (!st.path.empty()) {
                const Edge& previous = graph_.edges[st.path.back()];
                if (previous.type == EdgeType::NS &&
                    e.type != EdgeType::Del &&
                    e.type != EdgeType::A &&
                    e.type != EdgeType::AAAA) {
                    continue;
                }
            }

            if (st.require_base_next && !is_base_type(e.type)) {
                skipped_semantic_after_semantic = true;
                continue;
            }
            // An induced semantic edge is executable only immediately after
            // the resource-record edge that induced it.
            if (!follows_inducing_record(e, st)) continue;

            const bool edge_may_change_query =
                e.type == EdgeType::CNAME ||
                e.type == EdgeType::DNAME ||
                e.type == EdgeType::Del;
            const NodeKind dst_kind = graph_.nodes[e.dst].kind;
            const bool edge_may_bind_symbol =
                dst_kind == NodeKind::Alpha ||
                dst_kind == NodeKind::Beta ||
                e.type == EdgeType::Del;

            std::string old_q;
            bool old_has_query_rewrite = false;
            std::string old_rewrite_start_name;
            if (edge_may_change_query) {
                old_q = st.q;
                old_has_query_rewrite = st.has_query_rewrite;
                old_rewrite_start_name = st.rewrite_start_name;
            }

            bool edge_old_has_alpha = false;
            bool edge_old_has_beta = false;
            std::string edge_old_alpha_binding;
            std::string edge_old_beta_binding;
            if (edge_may_bind_symbol) {
                edge_old_has_alpha = st.has_alpha;
                edge_old_has_beta = st.has_beta;
                edge_old_alpha_binding = st.alpha_binding;
                edge_old_beta_binding = st.beta_binding;
            }
            const bool old_require_base_next = st.require_base_next;
            const size_t old_rewrite_events_size = st.rewrite_events.size();

            st.path.push_back(eid);
            if (!advance_query(e, st)) {
                st.path.pop_back();
                if (edge_may_change_query) {
                    st.q = old_q;
                    st.has_query_rewrite = old_has_query_rewrite;
                    st.rewrite_start_name = old_rewrite_start_name;
                    st.rewrite_events.resize(old_rewrite_events_size);
                }
                if (edge_may_bind_symbol) {
                    st.has_alpha = edge_old_has_alpha;
                    st.has_beta = edge_old_has_beta;
                    st.alpha_binding = edge_old_alpha_binding;
                    st.beta_binding = edge_old_beta_binding;
                }
                st.require_base_next = old_require_base_next;
                continue;
            }
            advanced = true;
            dfs(start_alpha, st, e.dst, max_depth, out, emitted_paths, observer, view_observer, store_results, emitted_count);
            st.path.pop_back();
            if (edge_may_change_query) {
                st.q = old_q;
                st.has_query_rewrite = old_has_query_rewrite;
                st.rewrite_start_name = old_rewrite_start_name;
                st.rewrite_events.resize(old_rewrite_events_size);
            }
            if (edge_may_bind_symbol) {
                st.has_alpha = edge_old_has_alpha;
                st.has_beta = edge_old_has_beta;
                st.alpha_binding = edge_old_alpha_binding;
                st.beta_binding = edge_old_beta_binding;
            }
            st.require_base_next = old_require_base_next;
        }

        if (!advanced) {
            emit(start_alpha,
                 current,
                 st,
                 skipped_semantic_after_semantic
                     ? "semantic edge must be followed by base RR"
                     : "no reachable outgoing edge",
                 out,
                 emitted_paths,
                 observer,
                 view_observer,
                 store_results,
                 emitted_count);
        }
        cleanup();
    }

    bool bind_symbol_if_needed(TraversalState& st, int node) const {
        const Node& n = graph_.nodes[node];
        if (n.kind != NodeKind::Alpha && n.kind != NodeKind::Beta) return true;

        const std::string& node_suffix = helpers_.suffix_ref(node);
        const std::string val = st.q.empty() ? node_suffix : st.q;

        if (n.kind == NodeKind::Alpha) {
            if (!is_descendant_or_same(val, node_suffix) &&
                !is_descendant_or_same(node_suffix, val)) {
                return false;
            }

            if (!st.has_alpha) {
                st.has_alpha = true;
                st.alpha_binding = val;
                return true;
            }
            return symbolic_query_matches_name(st.alpha_binding, val);
        } else if (n.kind == NodeKind::Beta) {
            // Beta is the variable prefix before this node's suffix, not the
            // complete domain name.  For example, q=a.money.bank.com. at
            // beta.money.bank.com. binds beta=a; q=_.coinsbank.com. at
            // beta.coinsbank.com. binds beta=_.
            auto prefix = beta_prefix_for_query(val, node_suffix);
            if (!prefix.has_value()) {
                return false;
            }

            if (!st.has_beta) {
                st.has_beta = true;
                st.beta_binding = *prefix;
                return true;
            }
            if (!beta_prefixes_compatible(st.beta_binding, *prefix)) {
                return false;
            }
            if (st.beta_binding == "_" && *prefix != "_") {
                st.beta_binding = *prefix;
            }
            return true;
        }

        return true;
    }

    bool advance_query(const Edge& e, TraversalState& st) const {
        const Node& src = graph_.nodes[e.src];
        const Node& dst = graph_.nodes[e.dst];
        const std::string old_q = st.q;
        bool changed_query = false;

        if (e.type == EdgeType::CNAME) {
            st.q = helpers_.symbolic_stripped_name(dst.id);
            changed_query = true;
            st.has_query_rewrite = true;
        } else if (e.type == EdgeType::DNAME) {
            const std::string& owner_suffix = helpers_.suffix_ref(src.id);
            const std::string& target_suffix = helpers_.suffix_ref(dst.id);
            if (is_strict_descendant_of(st.q, owner_suffix)) {
                std::string prefix = st.q.substr(0, st.q.size() - owner_suffix.size());
                st.q = prefix + target_suffix;
            } else if (is_descendant_or_same(owner_suffix, st.q)) {
                // The current alpha query is still abstract and covers the
                // DNAME owner.  Keep a symbolic one-label binding so beta never
                // represents zero labels.
                st.q = "_." + target_suffix;
            } else {
                return false;
            }
            changed_query = true;
            st.has_query_rewrite = true;
        } else if (e.type == EdgeType::DRew || e.type == EdgeType::CRew) {
            // DRew/CRew continue with the already rewritten q.
        } else if (e.type == EdgeType::Del) {
            // A Del target is the owner selected for one concrete instance of
            // the alpha query class. Refine q before evaluating that owner's
            // base record; Del itself is not a rewrite.
            if (dst.kind == NodeKind::Concrete) {
                st.q = helpers_.symbolic_stripped_name(dst.id);
            } else if (dst.kind == NodeKind::Wildcard ||
                       dst.kind == NodeKind::Beta) {
                st.q = "_." + helpers_.suffix(dst.id);
            } else {
                return false;
            }
            st.has_alpha = true;
            st.alpha_binding = st.q;
        }

        st.require_base_next = !is_base_type(e.type);
        if (changed_query) {
            if (st.rewrite_start_name.empty()) {
                st.rewrite_start_name = helpers_.symbolic_stripped_name_ref(src.id);
            }
            st.rewrite_events.push_back(RewriteEvent{
                e.id,
                st.path.size(),
                old_q,
                st.q
            });
        }

        if (dst.kind == NodeKind::Alpha || dst.kind == NodeKind::Beta) {
            return bind_symbol_if_needed(st, dst.id);
        }
        if (dst.kind == NodeKind::Concrete || dst.kind == NodeKind::Wildcard) {
            if (e.type == EdgeType::NS) {
                // NS rdata names the delegated nameserver, not the queried
                // owner name.  It can be out-of-bailiwick or under a sibling
                // zone, so matching it against q would incorrectly hide real
                // delegation paths and LD/MG/DI reports.
                return true;
            }
            const std::string& target_name = helpers_.symbolic_stripped_name_ref(dst.id);
            if (dst.kind == NodeKind::Concrete &&
                !symbolic_query_matches_name(st.q, target_name)) {
                // TODO: The paper-style rule does not fully specify all
                // concrete-vs-symbolic matching cases.  We keep traversal alive
                // for suffix-compatible values and stop conflicting concrete q.
                return false;
            }
        }
        return true;
    }

    void emit(int start_alpha,
              int final_node,
              const TraversalState& st,
              const std::string& reason,
              std::vector<PathResult>& out,
              EmittedPathSet& emitted_paths,
              const PathObserver& observer,
              const PathViewObserver& view_observer,
              bool store_results,
              size_t& emitted_count) const {
        EmittedPathKey sig{start_alpha,
                           final_node,
                           reason,
                           st.q,
                           st.require_base_next,
                           st.path,
                           st.has_alpha,
                           st.has_beta,
                           st.has_alpha ? st.alpha_binding : std::string{},
                           st.has_beta ? st.beta_binding : std::string{}};
        if (!emitted_paths.insert(std::move(sig))) {
            return;
        }

        ++emitted_count;
        if (view_observer && !store_results) {
            PathView view{start_alpha,
                          final_node,
                          &st.path,
                          st.has_query_rewrite,
                          &st.q,
                          &st.rewrite_start_name,
                          &st.rewrite_events};
            view_observer(view);
            return;
        }

        std::map<std::string, std::string> bindings;
        if (st.has_alpha) bindings["alpha"] = st.alpha_binding;
        if (st.has_beta) bindings["beta"] = st.beta_binding;
        PathResult path{start_alpha,
                        final_node,
                        graph_.nodes[final_node].name,
                        st.path,
                        bindings,
                        reason,
                        st.has_query_rewrite,
                        st.q,
                        st.rewrite_start_name,
                        st.rewrite_events};
        if (observer) {
            observer(path);
        }
        if (store_results) {
            out.push_back(std::move(path));
        }
    }
};

struct BugReport {
    std::string kind;
    std::optional<std::string> zoneCut;
    std::optional<std::string> nameserver;
    std::optional<std::string> startName;
    std::optional<std::string> query;
    std::optional<std::string> rewrittenName;
    std::optional<std::string> server;
    std::optional<std::string> zone;
    std::vector<int> path;
    std::string reason;
};

class BugDetector {
public:
    explicit BugDetector(const SemanticGraph& graph,
                         bool server_views_complete = true)
        : graph_(graph),
          helpers_(graph),
          outgoing_by_node_(graph.nodes.size(), nullptr),
          entry_node_(graph.nodes.size(), 0),
          server_views_complete_(server_views_complete) {
        for (const auto& kv : graph_.outgoing_edges) {
            if (kv.first >= 0 && kv.first < static_cast<int>(outgoing_by_node_.size())) {
                outgoing_by_node_[kv.first] = &kv.second;
            }
        }
        for (int entry : collect_reachable_entry_nodes(graph_)) {
            if (entry >= 0 && entry < static_cast<int>(entry_node_.size())) {
                entry_node_[entry] = 1;
            }
        }
    }

    struct Timing {
        double delegation_seconds = 0.0;
        double czd_seconds = 0.0;
        double rewrite_seconds = 0.0;
    };

    std::vector<BugReport> detectAll(const std::vector<PathResult>& paths,
                                     Timing* timing = nullptr) {
        using Clock = std::chrono::steady_clock;
        auto seconds = [](Clock::time_point a, Clock::time_point b) {
            return std::chrono::duration<double>(b - a).count();
        };

        beginPathDetection();
        auto t0 = Clock::now();
        for (const PathResult& path : paths) {
            observePath(path);
        }
        auto t1 = Clock::now();
        std::vector<BugReport> result = finishPathDetection();
        auto t2 = Clock::now();

        if (timing) {
            // In streaming mode, CZD/rewrite checks run while each path is
            // observed.  Delegation reports need a final aggregate comparison.
            timing->delegation_seconds = seconds(t1, t2);
            timing->czd_seconds = 0.0;
            timing->rewrite_seconds = seconds(t0, t1);
        }

        return result;
    }

    void beginPathDetection() {
        reports_.clear();
        seen_reports_.clear();
        reachable_address_cache_.clear();
        matchable_rewrite_cache_.clear();
        known_zone_cache_.clear();
        stream_parent_views_.clear();
        stream_alpha_ns_views_.clear();
        stream_addr_by_zone_name_.clear();
        const size_t reserve_hint = graph_.zones.size() * 2 + graph_.servers.size() + 16;
        stream_parent_views_.reserve(reserve_hint);
        stream_alpha_ns_views_.reserve(reserve_hint);
        stream_addr_by_zone_name_.reserve(graph_.nodes.size() + 16);
    }

    void observePath(const PathResult& path) {
        if (!isAlphaStartedPath(path)) return;
        observeDelegationEdges(path.edges);
        detectCyclicZoneDependencyEdges(path.start_alpha, path.edges);
        detectRewriteFields(path.start_alpha,
                            path.final_node,
                            path.has_query_rewrite,
                            path.final_query,
                            path.rewrite_start_name,
                            path.rewrite_events,
                            path.edges);
    }

    void observePathView(const PathView& path) {
        if (!isAlphaStartedNode(path.start_alpha)) return;
        static const std::vector<int> empty_edges;
        static const std::vector<RewriteEvent> empty_events;
        static const std::string empty_string;
        const std::vector<int>& edges = path.edges ? *path.edges : empty_edges;
        const std::string& final_query = path.final_query ? *path.final_query : empty_string;
        const std::string& rewrite_start =
            path.rewrite_start_name ? *path.rewrite_start_name : empty_string;
        const std::vector<RewriteEvent>& rewrite_events =
            path.rewrite_events ? *path.rewrite_events : empty_events;

        observeDelegationEdges(edges);
        detectCyclicZoneDependencyEdges(path.start_alpha, edges);
        detectRewriteFields(path.start_alpha,
                            path.final_node,
                            path.has_query_rewrite,
                            final_query,
                            rewrite_start,
                            rewrite_events,
                            edges);
    }

    void absorbObservedFrom(const BugDetector& other) {
        for (const BugReport& report : other.reports_) {
            addReport(report);
        }
        mergeDelegationViewMap(stream_parent_views_, other.stream_parent_views_);
        mergeDelegationViewMap(stream_alpha_ns_views_, other.stream_alpha_ns_views_);
        for (const auto& [key, values] : other.stream_addr_by_zone_name_) {
            auto& dst = stream_addr_by_zone_name_[key];
            dst.insert(values.begin(), values.end());
        }
    }

    std::vector<BugReport> finishPathDetection(Timing* timing = nullptr) {
        using Clock = std::chrono::steady_clock;
        auto seconds = [](Clock::time_point a, Clock::time_point b) {
            return std::chrono::duration<double>(b - a).count();
        };
        auto t0 = Clock::now();
        finalizeDelegationBugs();
        detectStaleRecords();
        auto t1 = Clock::now();
        if (timing) {
            timing->delegation_seconds = seconds(t0, t1);
            timing->czd_seconds = 0.0;
            timing->rewrite_seconds = 0.0;
        }
        return reports_;
    }

private:
    struct DelegationView {
        int parent_zone = -1;
        std::string cut;
        std::set<std::string> parent_ns;
        std::map<std::string, std::set<std::string>> parent_glue;
        std::set<std::string> child_ns;
        std::map<std::string, std::set<std::string>> child_addr;
        std::vector<int> path;
        std::map<std::string, std::vector<int>> ns_path;
    };

    const SemanticGraph& graph_;
    SemanticHelpers helpers_;
    std::vector<const std::vector<int>*> outgoing_by_node_;
    std::vector<uint8_t> entry_node_;
    bool server_views_complete_ = true;
    std::vector<BugReport> reports_;
    std::unordered_set<std::string> seen_reports_;
    mutable std::unordered_map<int, bool> reachable_address_cache_;
    mutable std::unordered_map<std::string, bool> matchable_rewrite_cache_;
    mutable std::unordered_map<std::string, int> known_zone_cache_;
    std::unordered_map<std::pair<int, std::string>, DelegationView, IntStringPairHash> stream_parent_views_;
    std::unordered_map<std::pair<int, std::string>, DelegationView, IntStringPairHash> stream_alpha_ns_views_;
    std::unordered_map<std::pair<int, std::string>, std::set<std::string>, IntStringPairHash> stream_addr_by_zone_name_;

    static bool is_addr_type(EdgeType t) {
        return t == EdgeType::A || t == EdgeType::AAAA;
    }

    static bool is_rewrite_type(EdgeType t) {
        return t == EdgeType::CNAME ||
               t == EdgeType::DNAME ||
               t == EdgeType::CRew ||
               t == EdgeType::DRew;
    }

    const std::vector<int>& outgoing(int node) const {
        static const std::vector<int> empty;
        if (node < 0 || node >= static_cast<int>(outgoing_by_node_.size())) {
            return empty;
        }
        const std::vector<int>* edges = outgoing_by_node_[node];
        return edges == nullptr ? empty : *edges;
    }

    static void mergeDelegationView(DelegationView& dst, const DelegationView& src) {
        if (dst.parent_zone < 0) dst.parent_zone = src.parent_zone;
        if (dst.cut.empty()) dst.cut = src.cut;
        dst.parent_ns.insert(src.parent_ns.begin(), src.parent_ns.end());
        for (const auto& [ns, addrs] : src.parent_glue) {
            dst.parent_glue[ns].insert(addrs.begin(), addrs.end());
        }
        dst.child_ns.insert(src.child_ns.begin(), src.child_ns.end());
        for (const auto& [ns, addrs] : src.child_addr) {
            dst.child_addr[ns].insert(addrs.begin(), addrs.end());
        }
        if (dst.path.empty()) dst.path = src.path;
        for (const auto& [ns, path] : src.ns_path) {
            if (dst.ns_path.find(ns) == dst.ns_path.end()) {
                dst.ns_path[ns] = path;
            }
        }
    }

    static void mergeDelegationViewMap(
        std::unordered_map<std::pair<int, std::string>, DelegationView, IntStringPairHash>& dst,
        const std::unordered_map<std::pair<int, std::string>, DelegationView, IntStringPairHash>& src) {
        for (const auto& [key, view] : src) {
            mergeDelegationView(dst[key], view);
        }
    }

    void addReport(BugReport report) {
        std::ostringstream key;
        key << report.kind << "|"
            << report.zoneCut.value_or("") << "|"
            << report.nameserver.value_or("") << "|"
            << report.startName.value_or("") << "|"
            << report.query.value_or("") << "|"
            << report.rewrittenName.value_or("") << "|"
            << report.server.value_or("") << "|"
            << report.zone.value_or("") << "|"
            << report.reason;

        if (seen_reports_.insert(key.str()).second) {
            reports_.push_back(std::move(report));
        }
    }

    std::optional<int> findZone(int server, const std::string& origin) const {
        for (int zid : graph_.servers[server].zones) {
            if (graph_.zones[zid].origin == origin) return zid;
        }
        return std::nullopt;
    }

    bool hasReachableAddress(int node) const {
        auto cached = reachable_address_cache_.find(node);
        if (cached != reachable_address_cache_.end()) return cached->second;

        bool result = false;
        for (int eid : outgoing(node)) {
            const Edge& e = graph_.edges[eid];
            if (e.deleted) continue;
            if (e.reach == 1 && is_addr_type(e.type)) {
                result = true;
                break;
            }
        }
        reachable_address_cache_[node] = result;
        return result;
    }

    bool hasReachableRewriteOut(int node) const {
        for (int eid : outgoing(node)) {
            const Edge& e = graph_.edges[eid];
            if (e.deleted) continue;
            if (e.reach == 1 && is_rewrite_type(e.type)) return true;
        }
        return false;
    }

    bool hasMatchableReachableRewriteOut(int node, const std::string& q) const {
        const std::string key = std::to_string(node) + "|" + q;
        auto cached = matchable_rewrite_cache_.find(key);
        if (cached != matchable_rewrite_cache_.end()) return cached->second;

        bool result = false;
        for (int eid : outgoing(node)) {
            const Edge& e = graph_.edges[eid];
            if (e.deleted) continue;
            if (e.reach != 1 || !is_rewrite_type(e.type)) continue;
            std::string next_q = q;
            bool changed_query = false;
            if (advanceRewriteQuery(e, next_q, changed_query)) {
                result = true;
                break;
            }
        }
        matchable_rewrite_cache_[key] = result;
        return result;
    }

    std::optional<int> knownZoneForName(const std::string& name) const {
        auto cached = known_zone_cache_.find(name);
        if (cached != known_zone_cache_.end()) {
            if (cached->second < 0) return std::nullopt;
            return cached->second;
        }

        std::optional<int> best;
        size_t best_len = 0;
        for (const Zone& z : graph_.zones) {
            if (!is_descendant_or_same(name, z.origin)) continue;
            if (!best.has_value() || z.origin.size() > best_len) {
                best = z.id;
                best_len = z.origin.size();
            }
        }
        known_zone_cache_[name] = best.value_or(-1);
        return best;
    }

    bool isAlphaStartedPath(const PathResult& path) const {
        return isAlphaStartedNode(path.start_alpha);
    }

    bool isAlphaStartedNode(int node) const {
        return node >= 0 &&
               node < static_cast<int>(graph_.nodes.size()) &&
               (entry_node_[node] != 0 || helpers_.IsAlpha(node));
    }

    bool validDnsTextName(const std::string& q) const {
        if (q.size() > 253) return false;

        std::string label;
        for (char c : q) {
            if (c == '.') {
                if (label.size() > 63) return false;
                label.clear();
            } else {
                label.push_back(c);
            }
        }
        return label.size() <= 63;
    }

    void observeDelegationEdges(const std::vector<int>& edges) {
        std::vector<int> prefix;
        for (int eid : edges) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
            prefix.push_back(eid);

            const Edge& e = graph_.edges[eid];
            if (e.reach != 1) continue;

            const Node& src = graph_.nodes[e.src];
            const Node& dst = graph_.nodes[e.dst];

            if (e.type == EdgeType::NS && helpers_.IsAlpha(e.src)) {
                const std::string& cut = helpers_.suffix_ref(src.id);
                const std::string ns = dst.name;
                const std::pair<int, std::string> key{src.zone, cut};

                DelegationView& alpha_view = stream_alpha_ns_views_[key];
                alpha_view.parent_zone = src.zone;
                alpha_view.cut = cut;
                alpha_view.parent_ns.insert(ns);
                if (alpha_view.path.empty()) alpha_view.path = prefix;
                if (alpha_view.ns_path.find(ns) == alpha_view.ns_path.end()) {
                    alpha_view.ns_path[ns] = prefix;
                }

                if (graph_.zones[src.zone].origin != cut) {
                    DelegationView& parent_view = stream_parent_views_[key];
                    parent_view.parent_zone = src.zone;
                    parent_view.cut = cut;
                    parent_view.parent_ns.insert(ns);
                    if (parent_view.path.empty()) parent_view.path = prefix;
                    if (parent_view.ns_path.find(ns) == parent_view.ns_path.end()) {
                        parent_view.ns_path[ns] = prefix;
                    }
                }
            } else if (is_addr_type(e.type)) {
                stream_addr_by_zone_name_[{src.zone, src.name}].insert(
                    edge_type_name(e.type) + ":" + dst.name);
            }
        }
    }

    void finalizeDelegationBugs() {
        std::map<std::string, DelegationView> child_views_by_cut;
        for (const auto& [key, alpha_view] : stream_alpha_ns_views_) {
            int zone = key.first;
            if (zone < 0 || zone >= static_cast<int>(graph_.zones.size())) continue;
            if (graph_.zones[zone].origin != alpha_view.cut) continue;

            DelegationView& child_view = child_views_by_cut[alpha_view.cut];
            child_view.parent_zone = zone;
            child_view.cut = alpha_view.cut;
            if (child_view.path.empty()) child_view.path = alpha_view.path;
            child_view.child_ns.insert(alpha_view.parent_ns.begin(), alpha_view.parent_ns.end());
            for (const std::string& child_ns : alpha_view.parent_ns) {
                const auto& child_addr = stream_addr_by_zone_name_[{zone, child_ns}];
                child_view.child_addr[child_ns].insert(child_addr.begin(), child_addr.end());
            }
        }

        for (auto& [_, view] : stream_parent_views_) {
            auto child_view_it = child_views_by_cut.find(view.cut);
            if (child_view_it != child_views_by_cut.end()) {
                const DelegationView& child = child_view_it->second;
                view.child_ns.insert(child.child_ns.begin(), child.child_ns.end());
                for (const auto& kv : child.child_addr) {
                    view.child_addr[kv.first].insert(kv.second.begin(), kv.second.end());
                }
            }

            for (const std::string& ns : view.parent_ns) {
                view.parent_glue[ns] = stream_addr_by_zone_name_[{view.parent_zone, ns}];
                const std::vector<int>& ns_path = view.ns_path[ns];

                // A nameserver at the delegation cut is still in-bailiwick:
                // resolving its address also depends on parent-side glue.
                if (is_descendant_or_same(ns, view.cut) && view.parent_glue[ns].empty()) {
                    addReport(BugReport{
                        "MG",
                        view.cut,
                        ns,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        graph_.servers[graph_.zones[view.parent_zone].server].name,
                        graph_.zones[view.parent_zone].origin,
                        ns_path,
                        "in-bailiwick delegated nameserver lacks parent-side A/AAAA glue"
                    });
                }

                auto server_it = graph_.server_by_name.find(ns);
                if (server_it == graph_.server_by_name.end()) continue;

                int child_server = server_it->second;
                auto child_zone = findZone(child_server, view.cut);
                if (!child_zone.has_value()) {
                    // A sampled inventory may contain one authoritative copy
                    // of a zone rather than a copy from every delegated NS.
                    // Absence of (server, zone) is then unknown, not lame.
                    if (!server_views_complete_) continue;
                    addReport(BugReport{
                        "LD",
                        view.cut,
                        ns,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        graph_.servers[child_server].name,
                        std::nullopt,
                        ns_path,
                        "delegated nameserver exists but does not host the delegated child zone"
                    });
                    continue;
                }
            }
        }

        for (const auto& [_, view] : stream_parent_views_) {
            if (view.parent_ns.empty()) continue;

            if (view.child_ns.empty()) {
                bool child_zone_is_present = false;
                for (const Zone& zone : graph_.zones) {
                    if (zone.origin == view.cut) {
                        child_zone_is_present = true;
                        break;
                    }
                }

                // A sampled inventory may omit the delegated child entirely.
                // In that case an empty child view is unknown, not DI.
                if (!server_views_complete_ && !child_zone_is_present) {
                    continue;
                }

                addReport(BugReport{
                    "DI",
                    view.cut,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    graph_.zones[view.parent_zone].origin,
                    view.path,
                    "child-side NS missing"
                });
                continue;
            }

            if (view.parent_ns != view.child_ns) {
                addReport(BugReport{
                    "DI",
                    view.cut,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    graph_.zones[view.parent_zone].origin,
                    view.path,
                    "parent-side NS set differs from child-side NS set"
                });
                continue;
            }

            for (const std::string& ns : view.parent_ns) {
                if (!is_strict_descendant_of(ns, view.cut)) continue;
                auto pit = view.parent_glue.find(ns);
                auto cit = view.child_addr.find(ns);
                static const std::set<std::string> empty;
                const auto& paddr = pit == view.parent_glue.end() ? empty : pit->second;
                const auto& caddr = cit == view.child_addr.end() ? empty : cit->second;
                if (paddr != caddr) {
                    addReport(BugReport{
                        "DI",
                        view.cut,
                        ns,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        graph_.zones[view.parent_zone].origin,
                        view.path,
                        "parent-side glue differs from child-side address records"
                    });
                }
            }
        }
    }

    void detectStaleRecords() {
        // A traversal root is a node with no incoming graph edge at all.  A
        // stale/shadowed owner is different: it has incoming candidates, but
        // none of those candidates remains reachable after reach filtering.
        std::vector<uint8_t> has_incoming_edge(graph_.nodes.size(), 0);
        std::vector<uint8_t> has_reachable_incoming_edge(graph_.nodes.size(), 0);
        for (const Edge& e : graph_.edges) {
            if (e.deleted) continue;
            if (e.src < 0 || e.dst < 0 ||
                e.src >= static_cast<int>(graph_.nodes.size()) ||
                e.dst >= static_cast<int>(graph_.nodes.size())) {
                continue;
            }
            has_incoming_edge[e.dst] = 1;
            if (e.reach == 1) has_reachable_incoming_edge[e.dst] = 1;
        }

        std::unordered_map<int, std::vector<std::string>> dname_owners_by_zone;

        for (const Edge& e : graph_.edges) {
            if (e.deleted || !is_base_type(e.type)) continue;
            if (e.src < 0 || e.dst < 0 ||
                e.src >= static_cast<int>(graph_.nodes.size()) ||
                e.dst >= static_cast<int>(graph_.nodes.size())) {
                continue;
            }

            const Node& owner = graph_.nodes[e.src];
            if (e.type == EdgeType::DNAME) {
                dname_owners_by_zone[owner.zone].push_back(helpers_.suffix_ref(owner.id));
            }
        }

        for (const Edge& e : graph_.edges) {
            if (e.deleted || !is_base_type(e.type)) continue;
            if (e.src < 0 || e.src >= static_cast<int>(graph_.nodes.size())) continue;

            const Node& owner = graph_.nodes[e.src];
            if (helpers_.IsAlpha(owner.id)) continue;

            const std::string& owner_name = helpers_.symbolic_stripped_name_ref(owner.id);
            bool reported_shadow = false;

            auto dn_it = dname_owners_by_zone.find(owner.zone);
            if (dn_it != dname_owners_by_zone.end() && e.type != EdgeType::DNAME) {
                for (const std::string& dname_owner : dn_it->second) {
                    if (!is_strict_descendant_of(owner_name, dname_owner)) continue;
                    addStaleRecordReport(
                        e,
                        "resource record is shadowed by an ancestor DNAME subtree rewrite");
                    reported_shadow = true;
                    break;
                }
            }

            if (reported_shadow) continue;
            if (!has_incoming_edge[owner.id]) continue;
            if (has_reachable_incoming_edge[owner.id]) continue;
            if (owner_name == graph_.zones[owner.zone].origin) continue;

            addStaleRecordReport(
                e,
                "resource-record owner has incoming graph edges but none with reach=1");
        }
    }

    void addStaleRecordReport(const Edge& e, const std::string& reason) {
        const Node& owner = graph_.nodes[e.src];
        const Node& target = graph_.nodes[e.dst];
        addReport(BugReport{
            "STALE",
            std::nullopt,
            std::nullopt,
            helpers_.symbolic_stripped_name_ref(owner.id),
            e.record,
            target.name,
            graph_.servers[owner.server].name,
            graph_.zones[owner.zone].origin,
            std::vector<int>{e.id},
            reason
        });
    }

    void detectCyclicZoneDependencyEdges(int start_alpha,
                                         const std::vector<int>& edges) {
        std::unordered_set<int> seen_zones;
        std::vector<int> prefix;
        int start_zone = graph_.nodes[start_alpha].zone;
        seen_zones.insert(start_zone);
        for (int eid : edges) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
            prefix.push_back(eid);

            const Edge& e = graph_.edges[eid];
            if (e.type != EdgeType::Del || e.reach != 1) continue;

            int to = graph_.nodes[e.dst].zone;
            if (graph_.nodes[e.src].zone == to) continue;
            if (seen_zones.find(to) != seen_zones.end()) {
                addReport(BugReport{
                    "CZD",
                    graph_.zones[to].origin,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    graph_.zones[to].origin,
                    prefix,
                    "reachable delegation path returns to an already visited zone"
                });
                break;
            }
            seen_zones.insert(to);
        }
    }

    void detectRewriteFields(int start_alpha,
                             int final_node,
                             bool has_query_rewrite,
                             const std::string& final_query,
                             const std::string& rewrite_start_name,
                             const std::vector<RewriteEvent>& rewrite_events,
                             const std::vector<int>& edges) {
        if (!has_query_rewrite) return;

        std::string q = rewrite_events.empty()
            ? helpers_.symbolic_stripped_name_ref(start_alpha)
            : rewrite_events.front().before_q;
        const std::string alpha_start_name = q;
        const std::string report_start_name =
            rewrite_start_name.empty() ? alpha_start_name : rewrite_start_name;
        bool rewritten = false;
        bool loop_reported = false;
        std::unordered_set<std::string> seen_q;
        seen_q.reserve(rewrite_events.size() + 1);
        seen_q.insert(q);

        for (const RewriteEvent& ev : rewrite_events) {
            if (ev.edge < 0 || ev.edge >= static_cast<int>(graph_.edges.size())) continue;
            const Edge& e = graph_.edges[ev.edge];
            rewritten = true;
            const std::string& next_q = ev.after_q;

            if (!validDnsTextName(next_q)) {
                const size_t n = std::min(ev.prefix_len, edges.size());
                std::vector<int> prefix(edges.begin(), edges.begin() + n);
                addReport(BugReport{
                    "ML",
                    std::nullopt,
                    std::nullopt,
                    report_start_name,
                    ev.before_q,
                    next_q,
                    graph_.servers[graph_.nodes[e.src].server].name,
                    graph_.zones[graph_.nodes[e.src].zone].origin,
                    prefix,
                    "rewritten query violates DNS length limit"
                });
            }

            if (!loop_reported && seen_q.find(next_q) != seen_q.end()) {
                const size_t n = std::min(ev.prefix_len, edges.size());
                std::vector<int> prefix(edges.begin(), edges.begin() + n);
                addReport(BugReport{
                    "RL",
                    std::nullopt,
                    std::nullopt,
                    report_start_name,
                    next_q,
                    next_q,
                    graph_.servers[graph_.nodes[e.src].server].name,
                    graph_.zones[graph_.nodes[e.src].zone].origin,
                    prefix,
                    "CNAME/DNAME rewrite loop detected"
                });
                loop_reported = true;
            }

            seen_q.insert(next_q);
            q = next_q;
        }

        if (!final_query.empty()) {
            q = final_query;
        }

        if (rewritten &&
            final_node >= 0 &&
            final_node < static_cast<int>(graph_.nodes.size()) &&
            graph_.nodes[final_node].kind != NodeKind::Terminal &&
            !hasReachableAddress(final_node) &&
            !hasMatchableReachableRewriteOut(final_node, q)) {
            const std::string& target_name = helpers_.symbolic_stripped_name_ref(final_node);
            auto known_zone = knownZoneForName(target_name);
            if (!known_zone.has_value()) {
                return;
            }

            const Zone& z = graph_.zones[*known_zone];
            addReport(BugReport{
                "RB",
                std::nullopt,
                std::nullopt,
                report_start_name,
                q,
                target_name,
                graph_.servers[z.server].name,
                z.origin,
                edges,
                "path rewrites to target in known zone but target lacks A/AAAA"
            });
        }
    }

    void detectDelegationBugs(const std::vector<PathResult>& paths) {
        // Delegation bugs are also path bugs in this model: every NS/glue/address
        // fact used below must have appeared on a DFS path whose start was an alpha
        // node. We still inspect server/zone existence as metadata, but we do not
        // start a separate traversal from arbitrary graph nodes.
        std::map<std::pair<int, std::string>, DelegationView> parent_views;
        std::map<std::pair<int, std::string>, DelegationView> alpha_ns_views;
        std::map<std::pair<int, std::string>, std::set<std::string>> addr_by_zone_name;

        for (const PathResult& path : paths) {
            if (!isAlphaStartedPath(path)) continue;

            std::vector<int> prefix;
            for (int eid : path.edges) {
                if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
                prefix.push_back(eid);

                const Edge& e = graph_.edges[eid];
                if (e.reach != 1) continue;

                const Node& src = graph_.nodes[e.src];
                const Node& dst = graph_.nodes[e.dst];

                if (e.type == EdgeType::NS && helpers_.IsAlpha(e.src)) {
                    const std::string& cut = helpers_.suffix_ref(src.id);
                    const std::string ns = dst.name;
                    const std::pair<int, std::string> key{src.zone, cut};

                    DelegationView& alpha_view = alpha_ns_views[key];
                    alpha_view.parent_zone = src.zone;
                    alpha_view.cut = cut;
                    alpha_view.parent_ns.insert(ns);
                    if (alpha_view.path.empty()) alpha_view.path = prefix;
                    if (alpha_view.ns_path.find(ns) == alpha_view.ns_path.end()) {
                        alpha_view.ns_path[ns] = prefix;
                    }

                    // A parent-side delegation is an alpha NS edge whose cut is
                    // below the current zone origin. Apex NS records in the child
                    // zone are authoritative child-side data and are collected
                    // above, but not treated as new parent delegations.
                    if (graph_.zones[src.zone].origin != cut) {
                        DelegationView& parent_view = parent_views[key];
                        parent_view.parent_zone = src.zone;
                        parent_view.cut = cut;
                        parent_view.parent_ns.insert(ns);
                        if (parent_view.path.empty()) parent_view.path = prefix;
                        if (parent_view.ns_path.find(ns) == parent_view.ns_path.end()) {
                            parent_view.ns_path[ns] = prefix;
                        }
                    }
                } else if (is_addr_type(e.type)) {
                    addr_by_zone_name[{src.zone, src.name}].insert(
                        edge_type_name(e.type) + ":" + dst.name);
                }
            }
        }

        // Child-side DI data is authoritative zone data.  It is collected from
        // known alpha-started paths whose zone origin is exactly the delegated
        // cut, instead of being tied to whether each delegated NS has a Server
        // object.  Otherwise a lame/missing server would incorrectly become
        // "child-side NS missing" even when the child zone file is present.
        std::map<std::string, DelegationView> child_views_by_cut;
        for (const auto& [key, alpha_view] : alpha_ns_views) {
            int zone = key.first;
            if (zone < 0 || zone >= static_cast<int>(graph_.zones.size())) continue;
            if (graph_.zones[zone].origin != alpha_view.cut) continue;

            DelegationView& child_view = child_views_by_cut[alpha_view.cut];
            child_view.parent_zone = zone;
            child_view.cut = alpha_view.cut;
            if (child_view.path.empty()) child_view.path = alpha_view.path;
            child_view.child_ns.insert(alpha_view.parent_ns.begin(), alpha_view.parent_ns.end());
            for (const std::string& child_ns : alpha_view.parent_ns) {
                const auto& child_addr = addr_by_zone_name[{zone, child_ns}];
                child_view.child_addr[child_ns].insert(child_addr.begin(), child_addr.end());
            }
        }

        for (auto& [_, view] : parent_views) {
            auto child_view_it = child_views_by_cut.find(view.cut);
            if (child_view_it != child_views_by_cut.end()) {
                const DelegationView& child = child_view_it->second;
                view.child_ns.insert(child.child_ns.begin(), child.child_ns.end());
                for (const auto& kv : child.child_addr) {
                    view.child_addr[kv.first].insert(kv.second.begin(), kv.second.end());
                }
            }

            for (const std::string& ns : view.parent_ns) {
                view.parent_glue[ns] = addr_by_zone_name[{view.parent_zone, ns}];
                const std::vector<int>& ns_path = view.ns_path[ns];

                // Bailiwick includes both the delegated name itself and names
                // below it.  Excluding equality misses circular apex NS names.
                if (is_descendant_or_same(ns, view.cut) && view.parent_glue[ns].empty()) {
                    addReport(BugReport{
                        "MG",
                        view.cut,
                        ns,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        graph_.servers[graph_.zones[view.parent_zone].server].name,
                        graph_.zones[view.parent_zone].origin,
                        ns_path,
                        "in-bailiwick delegated nameserver lacks parent-side A/AAAA glue"
                    });
                }

                auto server_it = graph_.server_by_name.find(ns);
                if (server_it == graph_.server_by_name.end()) continue;

                int child_server = server_it->second;
                auto child_zone = findZone(child_server, view.cut);
                if (!child_zone.has_value()) {
                    if (!server_views_complete_) continue;
                    addReport(BugReport{
                        "LD",
                        view.cut,
                        ns,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        graph_.servers[child_server].name,
                        std::nullopt,
                        ns_path,
                        "delegated nameserver exists but does not host the delegated child zone"
                    });
                    continue;
                }
            }
        }

        for (const auto& [_, view] : parent_views) {
            if (view.parent_ns.empty()) continue;

            if (view.child_ns.empty()) {
                bool child_zone_is_present = false;
                for (const Zone& zone : graph_.zones) {
                    if (zone.origin == view.cut) {
                        child_zone_is_present = true;
                        break;
                    }
                }

                // With sampled server views, absence of every child-zone file
                // is missing evidence rather than proof that child-side NS is
                // empty.  Complete inventories retain the original check.
                if (!server_views_complete_ && !child_zone_is_present) {
                    continue;
                }

                addReport(BugReport{
                    "DI",
                    view.cut,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    graph_.zones[view.parent_zone].origin,
                    view.path,
                    "child-side NS missing"
                });
                continue;
            }

            if (view.parent_ns != view.child_ns) {
                addReport(BugReport{
                    "DI",
                    view.cut,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    graph_.zones[view.parent_zone].origin,
                    view.path,
                    "parent-side NS set differs from child-side NS set"
                });
                continue;
            }

            for (const std::string& ns : view.parent_ns) {
                if (!is_strict_descendant_of(ns, view.cut)) continue;
                auto pit = view.parent_glue.find(ns);
                auto cit = view.child_addr.find(ns);
                static const std::set<std::string> empty;
                const auto& paddr = pit == view.parent_glue.end() ? empty : pit->second;
                const auto& caddr = cit == view.child_addr.end() ? empty : cit->second;
                if (paddr != caddr) {
                    addReport(BugReport{
                        "DI",
                        view.cut,
                        ns,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        graph_.zones[view.parent_zone].origin,
                        view.path,
                        "parent-side glue differs from child-side address records"
                    });
                }
            }
        }
    }

    void detectCyclicZoneDependency(const std::vector<PathResult>& paths) {
        for (const PathResult& path : paths) {
            if (!isAlphaStartedPath(path)) continue;

            std::unordered_set<int> seen_zones;
            std::vector<int> prefix;
            int start_zone = graph_.nodes[path.start_alpha].zone;
            seen_zones.insert(start_zone);
            for (int eid : path.edges) {
                if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
                prefix.push_back(eid);

                const Edge& e = graph_.edges[eid];
                if (e.type != EdgeType::Del || e.reach != 1) continue;

                int to = graph_.nodes[e.dst].zone;
                if (graph_.nodes[e.src].zone == to) continue;
                if (seen_zones.find(to) != seen_zones.end()) {
                    addReport(BugReport{
                        "CZD",
                        graph_.zones[to].origin,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        std::nullopt,
                        graph_.zones[to].origin,
                        prefix,
                        "reachable delegation path returns to an already visited zone"
                    });
                    break;
                }
                seen_zones.insert(to);
            }
        }
    }

    void detectRewriteBugs(const std::vector<PathResult>& paths) {
        for (const PathResult& path : paths) {
            if (!isAlphaStartedPath(path)) continue;
            if (!path.has_query_rewrite) continue;

            std::string q = path.rewrite_events.empty()
                ? helpers_.suffix_ref(path.start_alpha)
                : path.rewrite_events.front().before_q;
            const std::string alpha_start_name = q;
            const std::string report_start_name =
                path.rewrite_start_name.empty() ? alpha_start_name : path.rewrite_start_name;
            bool rewritten = false;
            bool loop_reported = false;
            std::unordered_set<std::string> seen_q;
            seen_q.reserve(path.rewrite_events.size() + 1);
            seen_q.insert(q);

            for (const RewriteEvent& ev : path.rewrite_events) {
                if (ev.edge < 0 || ev.edge >= static_cast<int>(graph_.edges.size())) continue;
                const Edge& e = graph_.edges[ev.edge];
                rewritten = true;
                const std::string& next_q = ev.after_q;

                if (!validDnsTextName(next_q)) {
                    const size_t n = std::min(ev.prefix_len, path.edges.size());
                    std::vector<int> prefix(path.edges.begin(), path.edges.begin() + n);
                    addReport(BugReport{
                        "ML",
                        std::nullopt,
                        std::nullopt,
                        report_start_name,
                        ev.before_q,
                        next_q,
                        graph_.servers[graph_.nodes[e.src].server].name,
                        graph_.zones[graph_.nodes[e.src].zone].origin,
                        prefix,
                        "rewritten query violates DNS length limit"
                    });
                }

                if (!loop_reported && seen_q.find(next_q) != seen_q.end()) {
                    const size_t n = std::min(ev.prefix_len, path.edges.size());
                    std::vector<int> prefix(path.edges.begin(), path.edges.begin() + n);
                    addReport(BugReport{
                        "RL",
                        std::nullopt,
                        std::nullopt,
                        report_start_name,
                        next_q,
                        next_q,
                        graph_.servers[graph_.nodes[e.src].server].name,
                        graph_.zones[graph_.nodes[e.src].zone].origin,
                        prefix,
                        "CNAME/DNAME rewrite loop detected"
                    });
                    loop_reported = true;
                }

                seen_q.insert(next_q);
                q = next_q;
            }

            if (!path.final_query.empty()) {
                q = path.final_query;
            }

            if (rewritten &&
                path.final_node >= 0 &&
                path.final_node < static_cast<int>(graph_.nodes.size()) &&
                graph_.nodes[path.final_node].kind != NodeKind::Terminal &&
                !hasReachableAddress(path.final_node) &&
                !hasMatchableReachableRewriteOut(path.final_node, q)) {
                const std::string& target_name = helpers_.symbolic_stripped_name_ref(path.final_node);
                auto known_zone = knownZoneForName(target_name);
                if (!known_zone.has_value()) {
                    continue;
                }

                const Zone& z = graph_.zones[*known_zone];
                addReport(BugReport{
                    "RB",
                    std::nullopt,
                    std::nullopt,
                    report_start_name,
                    q,
                    target_name,
                    graph_.servers[z.server].name,
                    z.origin,
                    path.edges,
                    "path rewrites to target in known zone but target lacks A/AAAA"
                });
            }
        }
    }

    bool advanceRewriteQuery(const Edge& e,
                             std::string& q,
                             bool& changed_query) const {
        const Node& src = graph_.nodes[e.src];
        const Node& dst = graph_.nodes[e.dst];

        if (e.type == EdgeType::CNAME) {
            q = helpers_.symbolic_stripped_name_ref(dst.id);
            changed_query = true;
        } else if (e.type == EdgeType::DNAME) {
            const std::string& owner_suffix = helpers_.suffix_ref(src.id);
            const std::string& target_suffix = helpers_.suffix_ref(dst.id);
            if (is_strict_descendant_of(q, owner_suffix)) {
                std::string prefix = q.substr(0, q.size() - owner_suffix.size());
                q = prefix + target_suffix;
            } else if (is_descendant_or_same(owner_suffix, q)) {
                q = "_." + target_suffix;
            } else {
                return false;
            }
            changed_query = true;
        } else if (e.type == EdgeType::CRew || e.type == EdgeType::DRew) {
            if (dst.kind == NodeKind::Concrete &&
                !symbolic_query_matches_name(q, helpers_.symbolic_stripped_name_ref(dst.id))) {
                return false;
            }
        }

        return true;
    }
};

struct IncrementalResult {
    std::vector<int> changed_edges;
    std::vector<int> reach_1_to_0;
    std::vector<int> reach_0_to_1;
    std::vector<int> added_edges;
    std::vector<int> removed_edges;
    std::vector<int> touched_nodes;
    std::vector<int> traversal_starts;
    std::vector<PathResult> affected_paths;
    std::vector<BugReport> new_reports;
    std::vector<BugReport> fixed_reports;
    std::vector<BugReport> all_reports_after;
    std::vector<std::string> warnings;
    double graph_update_seconds = 0.0;
    double local_traversal_seconds = 0.0;
    double report_refresh_seconds = 0.0;
    double total_seconds = 0.0;
};

enum class RepairOp {
    ADD,
    DELETE,
    MODIFY
};

struct RepairAction {
    RepairOp op = RepairOp::ADD;
    std::string target_server;
    std::string target_zone;
    std::optional<RecordInput> old_record;
    std::optional<RecordInput> new_record;
    std::string rationale;
};

class IncrementalValidator {
public:
    explicit IncrementalValidator(SemanticGraph& graph,
                                  bool server_views_complete = true)
        : graph_(graph),
          reach_index_(graph_),
          server_views_complete_(server_views_complete) {
        buildIncrementalIndexes();
        refreshBugCache();
    }

    IncrementalValidator(SemanticGraph& graph,
                         std::vector<BugReport> bug_cache,
                         bool server_views_complete = true)
        : graph_(graph),
          reach_index_(graph_),
          bug_cache_(std::move(bug_cache)),
          server_views_complete_(server_views_complete) {
        buildIncrementalIndexes();
    }

    IncrementalResult Add(const RecordInput& record) {
        IncrementalResult result;
        std::vector<BugReport> before = bug_cache_;
        zone_routing_changes_.clear();

        std::set<int> affected;
        int base = addBaseRecord(record, result.added_edges, result.touched_nodes, affected);
        if (base >= 0) {
            affected.insert(base);
        }

        rebuildSemanticCandidates(result.added_edges, result.touched_nodes, affected);
        rebuildOriginEdges(result.added_edges,
                           result.removed_edges,
                           result.touched_nodes,
                           affected);
        collectConservativeAffectedEdges(affected, result.touched_nodes);
        recomputeAffectedReach(affected, result);
        finishIncrementalResult(before, result);
        return result;
    }

    IncrementalResult Delete(const RecordInput& record) {
        IncrementalResult result;
        std::vector<BugReport> before = bug_cache_;
        zone_routing_changes_.clear();

        std::set<int> affected;
        softDeleteRecord(record,
                         result.removed_edges,
                         result.touched_nodes,
                         affected);

        rebuildSemanticCandidates(result.added_edges, result.touched_nodes, affected);
        rebuildOriginEdges(result.added_edges,
                           result.removed_edges,
                           result.touched_nodes,
                           affected);
        collectConservativeAffectedEdges(affected, result.touched_nodes);
        recomputeAffectedReach(affected, result);
        finishIncrementalResult(before, result);
        return result;
    }

    IncrementalResult Modify(const RecordInput& old_record, const RecordInput& new_record) {
        IncrementalResult result;
        std::vector<BugReport> before = bug_cache_;
        zone_routing_changes_.clear();

        std::set<int> affected;
        softDeleteRecord(old_record,
                         result.removed_edges,
                         result.touched_nodes,
                         affected);

        int new_base = addBaseRecord(new_record, result.added_edges, result.touched_nodes, affected);
        if (new_base >= 0) affected.insert(new_base);

        rebuildSemanticCandidates(result.added_edges, result.touched_nodes, affected);
        rebuildOriginEdges(result.added_edges,
                           result.removed_edges,
                           result.touched_nodes,
                           affected);
        collectConservativeAffectedEdges(affected, result.touched_nodes);
        recomputeAffectedReach(affected, result);
        finishIncrementalResult(before, result);
        return result;
    }

    IncrementalResult ApplyChangeSequence(const std::vector<RepairAction>& actions,
                                          bool compute_full_reports = true,
                                          bool compute_affected_paths = true,
                                          bool recompute_reach = true) {
        using Clock = std::chrono::steady_clock;
        auto elapsed = [](Clock::time_point begin, Clock::time_point end) {
            return std::chrono::duration<double>(end - begin).count();
        };
        const auto total_start = Clock::now();
        IncrementalResult result;
        std::vector<BugReport> before = bug_cache_;
        std::set<int> affected;
        zone_routing_changes_.clear();

        for (const RepairAction& action : actions) {
            if (action.op == RepairOp::ADD) {
                if (!action.new_record.has_value()) {
                    result.warnings.push_back("ADD action has no new_record");
                    continue;
                }
                int base = addBaseRecord(*action.new_record, result.added_edges, result.touched_nodes, affected);
                if (base >= 0) affected.insert(base);
            } else if (action.op == RepairOp::DELETE) {
                if (!action.old_record.has_value()) {
                    result.warnings.push_back("DELETE action has no old_record");
                    continue;
                }
                softDeleteRecord(*action.old_record,
                                 result.removed_edges,
                                 result.touched_nodes,
                                 affected);
            } else if (action.op == RepairOp::MODIFY) {
                if (!action.old_record.has_value() || !action.new_record.has_value()) {
                    result.warnings.push_back("MODIFY action needs old_record and new_record");
                    continue;
                }
                softDeleteRecord(*action.old_record,
                                 result.removed_edges,
                                 result.touched_nodes,
                                 affected);
                int base = addBaseRecord(*action.new_record, result.added_edges, result.touched_nodes, affected);
                if (base >= 0) affected.insert(base);
            }
        }

        if (recompute_reach) {
            rebuildSemanticCandidates(result.added_edges, result.touched_nodes, affected);
            rebuildOriginEdges(result.added_edges,
                               result.removed_edges,
                               result.touched_nodes,
                               affected);
            collectConservativeAffectedEdges(affected, result.touched_nodes);
            recomputeAffectedReach(affected, result);
        }
        result.graph_update_seconds = elapsed(total_start, Clock::now());
        finishIncrementalResult(before, result, compute_full_reports, compute_affected_paths);
        result.total_seconds = elapsed(total_start, Clock::now());
        return result;
    }

    int get_forward_record_start(int edge_id, std::vector<std::string>* warnings = nullptr) const {
        std::set<int> seen;
        int current = edge_id;
        while (current >= 0 && current < static_cast<int>(graph_.edges.size())) {
            if (!seen.insert(current).second) break;
            const Edge& e = graph_.edges[current];
            if (is_base_type(e.type)) return e.src;
            if (e.type == EdgeType::Org) return e.dst;

            auto it = graph_.semantic_edge_origin.find(current);
            if (it == graph_.semantic_edge_origin.end()) {
                if (warnings) {
                    warnings->push_back(
                        "semantic edge has no origin; fallback to src(e): edge " +
                        std::to_string(current));
                }
                return e.src;
            }
            current = it->second;
        }

        if (edge_id >= 0 && edge_id < static_cast<int>(graph_.edges.size())) {
            if (warnings) {
                warnings->push_back(
                    "semantic edge origin chain is invalid; fallback to src(e): edge " +
                    std::to_string(edge_id));
            }
            return graph_.edges[edge_id].src;
        }
        return -1;
    }

    std::vector<int> collect_traversal_starts(const std::vector<int>& changed_edges,
                                              const std::vector<int>& added_edges,
                                              const std::vector<int>& removed_edges,
                                              std::vector<std::string>* warnings = nullptr) const {
        std::set<int> starts;
        auto collect = [&](const std::vector<int>& edges) {
            for (int eid : edges) {
                if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
                if (graph_.edges[eid].type == EdgeType::Org) {
                    starts.insert(graph_.edges[eid].dst);
                    continue;
                }
                if (!is_base_type(graph_.edges[eid].type) &&
                    graph_.semantic_edge_origin.find(eid) == graph_.semantic_edge_origin.end()) {
                    if (warnings) {
                        warnings->push_back(
                            "new semantic edge has no origin yet; skip traversal start: edge " +
                            std::to_string(eid));
                    }
                    continue;
                }
                int start = get_forward_record_start(eid, warnings);
                if (start >= 0) starts.insert(start);
            }
        };
        collect(changed_edges);
        collect(added_edges);
        collect(removed_edges);
        return std::vector<int>(starts.begin(), starts.end());
    }

private:
    struct LocalSemanticIndex {
        std::unordered_map<int, std::unordered_map<std::string, std::vector<int>>>
            del_by_server_cut;
        std::unordered_map<std::string, std::vector<int>> concrete_by_name;
        std::unordered_map<std::string, std::vector<int>> wildcard_by_parent;
        std::unordered_map<std::string, std::vector<int>> beta_by_suffix;
        std::unordered_map<std::string, std::vector<int>> concrete_desc_by_suffix;
        std::unordered_map<std::string, std::vector<int>> wildcard_desc_by_suffix;
        std::unordered_map<std::string, std::vector<int>> beta_desc_by_suffix;

        std::unordered_map<std::string,
            std::unordered_map<std::string, std::vector<int>>> ns_by_server_cut;
        std::unordered_map<std::string, std::vector<int>> cname_by_exact_name;
        std::unordered_map<std::string, std::vector<int>> cname_by_parent;
        std::unordered_map<std::string, std::vector<int>> cname_by_beta_suffix;
        std::unordered_map<std::string, std::vector<int>> dname_by_source_suffix;
        std::unordered_map<std::string, std::vector<int>> dname_desc_by_suffix;

        std::vector<uint8_t> owner_node_indexed;
        std::vector<uint8_t> origin_base_indexed;
    };

    SemanticGraph& graph_;
    ReachComputer reach_index_;
    std::vector<BugReport> bug_cache_;
    std::unordered_map<EdgeKey, int, EdgeKeyHash> edge_by_key_;
    std::unordered_map<std::string, int> base_record_by_key_;
    std::unordered_map<int, std::vector<int>> incoming_edges_;
    std::vector<int> base_edge_ids_;
    std::vector<uint32_t> active_non_org_incoming_;
    std::vector<int> org_edge_by_dst_;
    std::vector<uint8_t> runtime_edge_indexed_;
    std::unordered_map<int, std::vector<int>> semantic_edges_by_src_server_;
    std::unordered_map<uint64_t, std::vector<int>> semantic_edges_by_dst_context_;
    std::unordered_map<int, std::vector<int>> org_edges_by_zone_;
    LocalSemanticIndex semantic_index_;
    IdMarker node_candidate_marker_;
    IdMarker base_candidate_marker_;
    std::set<std::string> zone_routing_changes_;
    bool server_views_complete_ = true;

    static std::string reportKey(const BugReport& report) {
        std::ostringstream key;
        key << report.kind << "|"
            << report.zoneCut.value_or("") << "|"
            << report.nameserver.value_or("") << "|"
            << report.startName.value_or("") << "|"
            << report.query.value_or("") << "|"
            << report.rewrittenName.value_or("") << "|"
            << report.server.value_or("") << "|"
            << report.zone.value_or("") << "|"
            << report.reason;
        return key.str();
    }

    static NodeKind classifyOwner(const std::string& name) {
        if (name.rfind(kAlphaPrefix, 0) == 0) return NodeKind::Alpha;
        if (name.rfind(kBetaPrefix, 0) == 0) return NodeKind::Beta;
        if (name.rfind("*.", 0) == 0) return NodeKind::Wildcard;
        return NodeKind::Concrete;
    }

    static NodeKind classifyTarget(EdgeType type, const std::string& name) {
        if (type == EdgeType::A || type == EdgeType::AAAA ||
            type == EdgeType::TXT || type == EdgeType::MX) {
            return NodeKind::Terminal;
        }
        return classifyOwner(name);
    }

    static std::string normalizeRdata(EdgeType type, const std::string& rdata) {
        if (type == EdgeType::A || type == EdgeType::AAAA || type == EdgeType::TXT) {
            return trim(rdata);
        }
        if (type == EdgeType::MX || type == EdgeType::NS ||
            type == EdgeType::CNAME || type == EdgeType::DNAME) {
            return normalize_domain(rdata);
        }
        return trim(rdata);
    }

    static RecordInput normalizedRecord(const RecordInput& r) {
        return RecordInput{
            normalize_domain(r.server),
            normalize_domain(r.zone),
            normalize_domain(r.owner),
            r.type,
            normalizeRdata(r.type, r.rdata)
        };
    }

    static std::string recordText(const RecordInput& r) {
        std::ostringstream rec;
        rec << r.owner << " " << edge_type_name(r.type) << " " << r.rdata;
        return rec.str();
    }

    static EdgeKey edgeKey(int src,
                           int dst,
                           EdgeType type,
                           const std::string& record) {
        return EdgeKey{src, dst, type, record};
    }

    std::string baseRecordLookupKey(const RecordInput& raw) const {
        RecordInput r = normalizedRecord(raw);
        std::string src_name = r.owner;
        std::string dst_name = r.rdata;
        if (r.type == EdgeType::NS) {
            src_name = alpha_name(r.owner);
        } else if (r.type == EdgeType::DNAME) {
            src_name = beta_name(r.owner);
            dst_name = beta_name(r.rdata);
        }

        return r.server + "|" + r.zone + "|" +
               src_name + "|" + dst_name + "|" +
               std::to_string(static_cast<int>(r.type)) + "|" +
               recordText(r);
    }

    std::string baseRecordLookupKey(const Edge& e) const {
        if (e.src < 0 || e.src >= static_cast<int>(graph_.nodes.size()) ||
            e.dst < 0 || e.dst >= static_cast<int>(graph_.nodes.size()) ||
            !is_base_type(e.type)) {
            return "";
        }
        const Node& src = graph_.nodes[e.src];
        const Node& dst = graph_.nodes[e.dst];
        return graph_.servers[src.server].name + "|" +
               graph_.zones[src.zone].origin + "|" +
               src.name + "|" + dst.name + "|" +
               std::to_string(static_cast<int>(e.type)) + "|" +
               e.record;
    }

    void buildIncrementalIndexes() {
        edge_by_key_.clear();
        base_record_by_key_.clear();
        incoming_edges_.clear();
        base_edge_ids_.clear();
        semantic_edges_by_src_server_.clear();
        semantic_edges_by_dst_context_.clear();
        org_edges_by_zone_.clear();
        semantic_index_ = LocalSemanticIndex{};
        edge_by_key_.reserve(graph_.edges.size() * 2 + 1);
        base_record_by_key_.reserve(graph_.edges.size() + 1);
        base_edge_ids_.reserve(graph_.edges.size());
        active_non_org_incoming_.assign(graph_.nodes.size(), 0);
        org_edge_by_dst_.assign(graph_.nodes.size(), -1);
        runtime_edge_indexed_.assign(graph_.edges.size(), 0);
        semantic_index_.owner_node_indexed.assign(graph_.nodes.size(), 0);
        semantic_index_.origin_base_indexed.assign(graph_.edges.size(), 0);
        node_candidate_marker_.resize(graph_.nodes.size());
        base_candidate_marker_.resize(graph_.edges.size());

        for (const Edge& e : graph_.edges) {
            edge_by_key_[edgeKey(e.src, e.dst, e.type, e.record)] = e.id;
            incoming_edges_[e.dst].push_back(e.id);
            indexRuntimeEdge(e.id);
            if (!e.deleted && e.type != EdgeType::Org &&
                e.dst >= 0 && e.dst < static_cast<int>(active_non_org_incoming_.size())) {
                ++active_non_org_incoming_[e.dst];
            }
            if (is_base_type(e.type)) {
                base_edge_ids_.push_back(e.id);
                const std::string key = baseRecordLookupKey(e);
                if (!key.empty()) {
                    base_record_by_key_[key] = e.id;
                }
            }
        }

        SemanticHelpers h(graph_);
        for (const Node& node : graph_.nodes) {
            if (reach_index_.HasOwnerOutgoing(node.id)) {
                indexOwnerNode(node.id, h);
            }
        }
        for (int eid : base_edge_ids_) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size()) ||
                graph_.edges[eid].deleted) {
                continue;
            }
            indexOriginBase(eid, h);
        }
    }

    static uint64_t nodeContextKey(int server, int zone) {
        return (static_cast<uint64_t>(static_cast<uint32_t>(server)) << 32) |
               static_cast<uint32_t>(zone);
    }

    void ensureIncrementalCapacity() {
        if (active_non_org_incoming_.size() < graph_.nodes.size()) {
            active_non_org_incoming_.resize(graph_.nodes.size(), 0);
            org_edge_by_dst_.resize(graph_.nodes.size(), -1);
            semantic_index_.owner_node_indexed.resize(graph_.nodes.size(), 0);
            node_candidate_marker_.ensure_size(graph_.nodes.size());
        }
        if (runtime_edge_indexed_.size() < graph_.edges.size()) {
            runtime_edge_indexed_.resize(graph_.edges.size(), 0);
            semantic_index_.origin_base_indexed.resize(graph_.edges.size(), 0);
            base_candidate_marker_.ensure_size(graph_.edges.size());
        }
    }

    void indexRuntimeEdge(int edge_id) {
        if (edge_id < 0 || edge_id >= static_cast<int>(graph_.edges.size())) return;
        ensureIncrementalCapacity();
        if (runtime_edge_indexed_[edge_id]) return;
        runtime_edge_indexed_[edge_id] = 1;

        const Edge& e = graph_.edges[edge_id];
        if (e.type == EdgeType::Org) {
            if (e.dst >= 0 && e.dst < static_cast<int>(org_edge_by_dst_.size())) {
                org_edge_by_dst_[e.dst] = e.id;
                const int zone = graph_.nodes[e.dst].zone;
                if (zone >= 0) org_edges_by_zone_[zone].push_back(e.id);
            }
            return;
        }
        if (!is_semantic_type(e.type)) return;

        if (e.src >= 0 && e.src < static_cast<int>(graph_.nodes.size())) {
            const int server = graph_.nodes[e.src].server;
            if (server >= 0) semantic_edges_by_src_server_[server].push_back(e.id);
        }
        if (e.dst >= 0 && e.dst < static_cast<int>(graph_.nodes.size())) {
            const Node& dst = graph_.nodes[e.dst];
            if (dst.server >= 0 && dst.zone >= 0) {
                semantic_edges_by_dst_context_[
                    nodeContextKey(dst.server, dst.zone)].push_back(e.id);
            }
        }
    }

    void indexOwnerNode(int node_id, const SemanticHelpers& h) {
        if (node_id < 0 || node_id >= static_cast<int>(graph_.nodes.size()) ||
            !reach_index_.HasOwnerOutgoing(node_id)) {
            return;
        }
        ensureIncrementalCapacity();
        if (semantic_index_.owner_node_indexed[node_id]) return;
        semantic_index_.owner_node_indexed[node_id] = 1;

        const Node& node = graph_.nodes[node_id];
        if (h.IsAlpha(node_id)) return;
        const std::string& raw = h.symbolic_stripped_name_ref(node_id);
        const std::string& suffix = h.suffix_ref(node_id);
        std::unordered_set<std::string> cuts;
        for (const std::string& ancestor : ancestor_suffixes_inclusive(suffix)) {
            cuts.insert(ancestor);
        }
        for (const std::string& ancestor : ancestor_suffixes_inclusive(raw)) {
            cuts.insert(ancestor);
        }
        for (const std::string& cut : cuts) {
            semantic_index_.del_by_server_cut[node.server][cut].push_back(node_id);
        }

        if (h.IsConcrete(node_id)) {
            semantic_index_.concrete_by_name[node.name].push_back(node_id);
            for (const std::string& ancestor : ancestor_suffixes_proper(raw)) {
                semantic_index_.concrete_desc_by_suffix[ancestor].push_back(node_id);
            }
        } else if (h.IsWildcard(node_id)) {
            semantic_index_.wildcard_by_parent[raw].push_back(node_id);
            for (const std::string& ancestor : ancestor_suffixes_inclusive(raw)) {
                semantic_index_.wildcard_desc_by_suffix[ancestor].push_back(node_id);
            }
        } else if (h.IsBeta(node_id)) {
            semantic_index_.beta_by_suffix[suffix].push_back(node_id);
            for (const std::string& ancestor : ancestor_suffixes_inclusive(suffix)) {
                semantic_index_.beta_desc_by_suffix[ancestor].push_back(node_id);
            }
        }
    }

    void indexOriginBase(int edge_id, const SemanticHelpers& h) {
        if (edge_id < 0 || edge_id >= static_cast<int>(graph_.edges.size())) return;
        const Edge& edge = graph_.edges[edge_id];
        if (edge.deleted ||
            (edge.type != EdgeType::NS &&
             edge.type != EdgeType::CNAME &&
             edge.type != EdgeType::DNAME)) {
            return;
        }
        ensureIncrementalCapacity();
        if (semantic_index_.origin_base_indexed[edge_id]) return;
        semantic_index_.origin_base_indexed[edge_id] = 1;

        if (edge.type == EdgeType::NS) {
            const Node& owner = graph_.nodes[edge.src];
            const std::string& cut = h.suffix_ref(edge.src);
            if (owner.zone >= 0 && cut != graph_.zones[owner.zone].origin) {
                semantic_index_.ns_by_server_cut[
                    graph_.nodes[edge.dst].name][cut].push_back(edge_id);
            }
            return;
        }

        if (edge.type == EdgeType::CNAME) {
            const int source = edge.dst;
            const std::string& raw = h.symbolic_stripped_name_ref(source);
            semantic_index_.cname_by_exact_name[
                graph_.nodes[source].name].push_back(edge_id);
            if (auto parent = immediate_parent_suffix(raw)) {
                semantic_index_.cname_by_parent[*parent].push_back(edge_id);
            }
            const std::vector<std::string> beta_suffixes =
                h.IsBeta(source) ? ancestor_suffixes_inclusive(raw)
                                 : ancestor_suffixes_proper(raw);
            for (const std::string& suffix : beta_suffixes) {
                semantic_index_.cname_by_beta_suffix[suffix].push_back(edge_id);
            }
            return;
        }

        const std::string& source_suffix = h.suffix_ref(edge.dst);
        semantic_index_.dname_by_source_suffix[source_suffix].push_back(edge_id);
        for (const std::string& ancestor :
             ancestor_suffixes_inclusive(source_suffix)) {
            semantic_index_.dname_desc_by_suffix[ancestor].push_back(edge_id);
        }
    }

    int ensureServer(const std::string& name) {
        auto it = graph_.server_by_name.find(name);
        if (it != graph_.server_by_name.end()) return it->second;
        int id = static_cast<int>(graph_.servers.size());
        graph_.servers.push_back(Server{id, name, {}});
        graph_.server_by_name[name] = id;
        return id;
    }

    int ensureZone(int server, const std::string& origin) {
        ZoneKey key{server, origin};
        auto it = graph_.zone_by_server_origin.find(key);
        if (it != graph_.zone_by_server_origin.end()) return it->second;
        int id = static_cast<int>(graph_.zones.size());
        graph_.zones.push_back(Zone{id, origin, server, {}, {}, {}});
        graph_.zone_by_server_origin.emplace(std::move(key), id);
        graph_.servers[server].zones.push_back(id);
        return id;
    }

    static int kindRank(NodeKind k) {
        switch (k) {
            case NodeKind::Origin: return 6;
            case NodeKind::Alpha: return 5;
            case NodeKind::Beta: return 4;
            case NodeKind::Wildcard: return 3;
            case NodeKind::Concrete: return 2;
            case NodeKind::Terminal: return 1;
        }
        return 0;
    }

    int ensureNode(int server, int zone, const std::string& name, NodeKind kind) {
        Zone& z = graph_.zones[zone];
        auto it = z.node_by_name.find(name);
        if (it != z.node_by_name.end()) {
            int id = it->second;
            if (kindRank(kind) > kindRank(graph_.nodes[id].kind)) {
                graph_.nodes[id].kind = kind;
            }
            return id;
        }

        int id = static_cast<int>(graph_.nodes.size());
        graph_.nodes.push_back(Node{id, name, server, zone, kind});
        z.node_by_name[name] = id;
        z.nodes.push_back(id);
        ensureIncrementalCapacity();
        return id;
    }

    void recomputeNodeKind(int node_id) {
        if (node_id < 0 || node_id >= static_cast<int>(graph_.nodes.size())) {
            return;
        }
        Node& node = graph_.nodes[node_id];
        if (node.kind == NodeKind::Origin) return;

        bool found_active_base = false;
        NodeKind best = NodeKind::Terminal;
        auto consider = [&](NodeKind candidate) {
            if (!found_active_base || kindRank(candidate) > kindRank(best)) {
                best = candidate;
            }
            found_active_base = true;
        };

        auto outgoing = graph_.outgoing_edges.find(node_id);
        if (outgoing != graph_.outgoing_edges.end()) {
            for (int edge_id : outgoing->second) {
                if (edge_id < 0 ||
                    edge_id >= static_cast<int>(graph_.edges.size())) {
                    continue;
                }
                const Edge& edge = graph_.edges[edge_id];
                if (edge.deleted || !is_base_type(edge.type)) continue;
                consider(classifyOwner(node.name));
            }
        }

        auto incoming = incoming_edges_.find(node_id);
        if (incoming != incoming_edges_.end()) {
            for (int edge_id : incoming->second) {
                if (edge_id < 0 ||
                    edge_id >= static_cast<int>(graph_.edges.size())) {
                    continue;
                }
                const Edge& edge = graph_.edges[edge_id];
                if (edge.deleted || !is_base_type(edge.type)) continue;
                consider(classifyTarget(edge.type, node.name));
            }
        }

        if (found_active_base) node.kind = best;
    }

    void onEdgeActivated(int edge_id) {
        if (edge_id < 0 || edge_id >= static_cast<int>(graph_.edges.size())) return;
        ensureIncrementalCapacity();
        indexRuntimeEdge(edge_id);
        const Edge& edge = graph_.edges[edge_id];
        if (edge.type != EdgeType::Org &&
            edge.dst >= 0 &&
            edge.dst < static_cast<int>(active_non_org_incoming_.size())) {
            ++active_non_org_incoming_[edge.dst];
        }
        if (is_base_type(edge.type)) {
            reach_index_.OnBaseEdgeActivated(edge);
        }
    }

    void onEdgeDeactivated(int edge_id) {
        if (edge_id < 0 || edge_id >= static_cast<int>(graph_.edges.size())) return;
        const Edge& edge = graph_.edges[edge_id];
        if (edge.type != EdgeType::Org &&
            edge.dst >= 0 &&
            edge.dst < static_cast<int>(active_non_org_incoming_.size()) &&
            active_non_org_incoming_[edge.dst] != 0) {
            --active_non_org_incoming_[edge.dst];
        }
        if (is_base_type(edge.type)) {
            reach_index_.OnBaseEdgeDeactivated(edge);
        }
    }

    bool deactivateEdge(int edge_id,
                        std::vector<int>& removed_edges,
                        std::set<int>& affected) {
        if (edge_id < 0 || edge_id >= static_cast<int>(graph_.edges.size()) ||
            graph_.edges[edge_id].deleted) {
            return false;
        }
        onEdgeDeactivated(edge_id);
        graph_.edges[edge_id].deleted = true;
        removed_edges.push_back(edge_id);
        affected.insert(edge_id);
        return true;
    }

    int addEdge(int src,
                int dst,
                EdgeType type,
                const std::string& record,
                int origin,
                std::vector<int>& added_edges,
                std::set<int>& affected,
                bool forced_unreachable = false) {
        if (src < 0 || dst < 0) return -1;
        if (graph_.nodes[dst].kind == NodeKind::Alpha && type != EdgeType::Org) return -1;
        if (type == EdgeType::CRew && src == dst) return -1;

        EdgeKey key = edgeKey(src, dst, type, record);
        auto existing = edge_by_key_.find(key);
        if (existing != edge_by_key_.end()) {
            Edge& e = graph_.edges[existing->second];
            if (forced_unreachable && !e.forced_unreachable) {
                e.forced_unreachable = true;
                affected.insert(e.id);
            }
            if (origin >= 0) {
                graph_.semantic_edge_origin[e.id] = origin;
                auto& induced = graph_.induced_edge_index[origin];
                if (std::find(induced.begin(), induced.end(), e.id) == induced.end()) {
                    induced.push_back(e.id);
                }
            }
            if (e.deleted) {
                e.deleted = false;
                onEdgeActivated(e.id);
                added_edges.push_back(e.id);
                affected.insert(e.id);
            }
            return e.id;
        }

        int id = static_cast<int>(graph_.edges.size());
        graph_.edges.push_back(Edge{id, src, dst, type, 0, record, false, forced_unreachable});
        edge_by_key_.emplace(std::move(key), id);
        if (graph_.nodes[src].zone >= 0) {
            graph_.zones[graph_.nodes[src].zone].edges.push_back(id);
        }
        graph_.outgoing_edges[src].push_back(id);
        incoming_edges_[dst].push_back(id);
        if (is_base_type(type)) {
            base_edge_ids_.push_back(id);
        }
        if (origin >= 0) {
            graph_.semantic_edge_origin[id] = origin;
            graph_.induced_edge_index[origin].push_back(id);
        }
        onEdgeActivated(id);
        added_edges.push_back(id);
        affected.insert(id);
        return id;
    }

    int addBaseRecord(const RecordInput& raw,
                      std::vector<int>& added_edges,
                      std::vector<int>& touched_nodes,
                      std::set<int>& affected) {
        RecordInput r = normalizedRecord(raw);
        if (!is_base_type(r.type)) return -1;

        int server = ensureServer(r.server);
        int zone = ensureZone(server, r.zone);
        const bool zone_was_active = reach_index_.IsZoneActive(zone);
        std::string src_name = r.owner;
        std::string dst_name = r.rdata;
        NodeKind src_kind = classifyOwner(src_name);
        NodeKind dst_kind = classifyTarget(r.type, dst_name);

        if (r.type == EdgeType::NS) {
            src_name = alpha_name(r.owner);
            src_kind = NodeKind::Alpha;
            dst_kind = NodeKind::Concrete;
        } else if (r.type == EdgeType::DNAME) {
            src_name = beta_name(r.owner);
            dst_name = beta_name(r.rdata);
            src_kind = NodeKind::Beta;
            dst_kind = NodeKind::Beta;
        }

        int src = ensureNode(server, zone, src_name, src_kind);
        int dst = ensureNode(server, zone, dst_name, dst_kind);
        touched_nodes.push_back(src);
        touched_nodes.push_back(dst);
        int edge_id = addEdge(src, dst, r.type, recordText(r), -1, added_edges, affected);
        if (edge_id >= 0) {
            if (!zone_was_active && reach_index_.IsZoneActive(zone)) {
                zone_routing_changes_.insert(graph_.zones[zone].origin);
            }
            base_record_by_key_[baseRecordLookupKey(r)] = edge_id;
            SemanticHelpers h(graph_);
            indexOwnerNode(src, h);
            indexOriginBase(edge_id, h);
        }
        return edge_id;
    }

    int findBaseRecord(const RecordInput& raw) const {
        RecordInput r = normalizedRecord(raw);
        auto indexed = base_record_by_key_.find(baseRecordLookupKey(r));
        if (indexed != base_record_by_key_.end()) {
            return indexed->second;
        }
        return -1;
    }

    void softDeleteRecord(const RecordInput& record,
                          std::vector<int>& removed_edges,
                          std::vector<int>& touched_nodes,
                          std::set<int>& affected) {
        int base = findBaseRecord(record);
        if (base < 0 || graph_.edges[base].deleted) return;

        const int src = graph_.edges[base].src;
        const int dst = graph_.edges[base].dst;
        const int zone = graph_.nodes[src].zone;
        const bool zone_was_active = reach_index_.IsZoneActive(zone);
        if (!deactivateEdge(base, removed_edges, affected)) return;
        if (zone_was_active && !reach_index_.IsZoneActive(zone)) {
            zone_routing_changes_.insert(graph_.zones[zone].origin);
        }
        touched_nodes.push_back(src);
        touched_nodes.push_back(dst);

        auto induced = graph_.induced_edge_index.find(base);
        if (induced != graph_.induced_edge_index.end()) {
            for (int eid : induced->second) {
                if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) {
                    continue;
                }
                const int induced_src = graph_.edges[eid].src;
                const int induced_dst = graph_.edges[eid].dst;
                if (!deactivateEdge(eid, removed_edges, affected)) continue;
                touched_nodes.push_back(induced_src);
                touched_nodes.push_back(induced_dst);
            }
        }
        recomputeNodeKind(src);
        recomputeNodeKind(dst);
    }

    void rebuildSemanticCandidates(std::vector<int>& added_edges,
                                   const std::vector<int>& touched_nodes,
                                   std::set<int>& affected) {
        SemanticHelpers h(graph_);
        ensureIncrementalCapacity();
        base_candidate_marker_.next();
        std::vector<int> base_ids;
        auto add_base = [&](int eid) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) return;
            const Edge& edge = graph_.edges[eid];
            if (edge.deleted ||
                (edge.type != EdgeType::NS &&
                 edge.type != EdgeType::CNAME &&
                 edge.type != EdgeType::DNAME)) {
                return;
            }
            if (base_candidate_marker_.mark(eid)) base_ids.push_back(eid);
        };

        const std::vector<int> added_snapshot = added_edges;
        for (int eid : added_snapshot) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size()) ||
                !is_base_type(graph_.edges[eid].type)) {
                continue;
            }
            indexOriginBase(eid, h);
            add_base(eid);
        }

        node_candidate_marker_.next();
        for (int node : touched_nodes) {
            if (node < 0 || node >= static_cast<int>(graph_.nodes.size()) ||
                !node_candidate_marker_.mark(node) ||
                !reach_index_.HasOwnerOutgoing(node)) {
                continue;
            }
            indexOwnerNode(node, h);
            collectOriginsForTarget(node, h, base_ids);
        }

        for (int eid : base_ids) {
            const Edge& e = graph_.edges[eid];
            if (e.type == EdgeType::NS) {
                rebuildDelFor(e, h, added_edges, affected);
            } else if (e.type == EdgeType::DNAME) {
                rebuildDRewFor(e, h, added_edges, affected);
            } else if (e.type == EdgeType::CNAME) {
                rebuildCRewFor(e, h, added_edges, affected);
            }
        }
    }

    void rebuildOriginEdges(std::vector<int>& added_edges,
                            std::vector<int>& removed_edges,
                            std::vector<int>& touched_nodes,
                            std::set<int>& affected) {
        if (graph_.origin_node < 0) {
            graph_.origin_node = static_cast<int>(graph_.nodes.size());
            graph_.nodes.push_back(Node{
                graph_.origin_node, kOriginName, -1, -1, NodeKind::Origin
            });
            ensureIncrementalCapacity();
        }

        ensureIncrementalCapacity();
        node_candidate_marker_.next();
        std::vector<int> dirty_nodes;
        auto add_dirty = [&](int node) {
            if (node < 0 || node >= static_cast<int>(graph_.nodes.size())) return;
            if (node_candidate_marker_.mark(node)) dirty_nodes.push_back(node);
        };
        for (int node : touched_nodes) add_dirty(node);
        const std::vector<int> affected_snapshot(affected.begin(), affected.end());
        for (int eid : affected_snapshot) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
            const Edge& e = graph_.edges[eid];
            add_dirty(e.src);
            add_dirty(e.dst);
        }

        for (int node_id : dirty_nodes) {
            const Node& node = graph_.nodes[node_id];
            if (node.kind == NodeKind::Origin || node.kind == NodeKind::Terminal) continue;
            const bool desired =
                reach_index_.HasOwnerOutgoing(node_id) &&
                active_non_org_incoming_[node_id] == 0;
            const int existing = org_edge_by_dst_[node_id];
            if (existing >= 0) {
                Edge& edge = graph_.edges[existing];
                if (desired && edge.deleted) {
                    edge.deleted = false;
                    onEdgeActivated(existing);
                    added_edges.push_back(existing);
                    affected.insert(existing);
                    touched_nodes.push_back(node_id);
                } else if (!desired && !edge.deleted) {
                    deactivateEdge(existing, removed_edges, affected);
                    touched_nodes.push_back(node_id);
                } else if (!edge.deleted) {
                    affected.insert(existing);
                }
                continue;
            }

            if (!desired) continue;
            int eid = addEdge(graph_.origin_node,
                              node_id,
                              EdgeType::Org,
                              "graph entry",
                              -1,
                              added_edges,
                              affected);
            if (eid >= 0) touched_nodes.push_back(node_id);
        }
    }

    void appendNodeCandidates(
        const std::unordered_map<std::string, std::vector<int>>& index,
        const std::string& key,
        std::vector<int>& candidates) {
        auto it = index.find(key);
        if (it == index.end()) return;
        for (int node : it->second) {
            if (node_candidate_marker_.mark(node)) candidates.push_back(node);
        }
    }

    void appendOriginCandidates(
        const std::unordered_map<std::string, std::vector<int>>& index,
        const std::string& key,
        int target,
        const SemanticHelpers& h,
        std::vector<int>& base_ids) {
        auto it = index.find(key);
        if (it == index.end()) return;
        for (int eid : it->second) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
            const Edge& edge = graph_.edges[eid];
            if (edge.deleted || !semanticBaseMayInduceToNode(edge, target, h)) continue;
            if (base_candidate_marker_.mark(eid)) base_ids.push_back(eid);
        }
    }

    void collectOriginsForTarget(int target,
                                 const SemanticHelpers& h,
                                 std::vector<int>& base_ids) {
        if (target < 0 || target >= static_cast<int>(graph_.nodes.size()) ||
            !reach_index_.HasOwnerOutgoing(target) || h.IsAlpha(target)) {
            return;
        }

        const Node& node = graph_.nodes[target];
        const std::string& raw = h.symbolic_stripped_name_ref(target);
        const std::string& suffix = h.suffix_ref(target);
        const std::string& server_name = graph_.servers[node.server].name;
        auto ns_server = semantic_index_.ns_by_server_cut.find(server_name);
        if (ns_server != semantic_index_.ns_by_server_cut.end()) {
            std::unordered_set<std::string> cuts;
            for (const std::string& ancestor : ancestor_suffixes_inclusive(suffix)) {
                cuts.insert(ancestor);
            }
            for (const std::string& ancestor : ancestor_suffixes_inclusive(raw)) {
                cuts.insert(ancestor);
            }
            for (const std::string& cut : cuts) {
                appendOriginCandidates(
                    ns_server->second, cut, target, h, base_ids);
            }
        }

        if (h.IsConcrete(target)) {
            appendOriginCandidates(
                semantic_index_.cname_by_exact_name,
                node.name,
                target,
                h,
                base_ids);
            for (const std::string& ancestor : ancestor_suffixes_proper(raw)) {
                appendOriginCandidates(
                    semantic_index_.dname_by_source_suffix,
                    ancestor,
                    target,
                    h,
                    base_ids);
            }
        } else if (h.IsWildcard(target)) {
            appendOriginCandidates(
                semantic_index_.cname_by_parent,
                raw,
                target,
                h,
                base_ids);
            for (const std::string& ancestor : ancestor_suffixes_inclusive(raw)) {
                appendOriginCandidates(
                    semantic_index_.dname_by_source_suffix,
                    ancestor,
                    target,
                    h,
                    base_ids);
            }
        } else if (h.IsBeta(target)) {
            appendOriginCandidates(
                semantic_index_.cname_by_beta_suffix,
                suffix,
                target,
                h,
                base_ids);
            appendOriginCandidates(
                semantic_index_.dname_desc_by_suffix,
                suffix,
                target,
                h,
                base_ids);
            for (const std::string& ancestor :
                 ancestor_suffixes_inclusive(suffix)) {
                appendOriginCandidates(
                    semantic_index_.dname_by_source_suffix,
                    ancestor,
                    target,
                    h,
                    base_ids);
            }
        }
    }

    bool semanticBaseMayInduceToNode(const Edge& base,
                                     int target,
                                     const SemanticHelpers& h) const {
        if (!h.HasOwnerOutgoing(target)) return false;
        if (h.IsAlpha(target)) return false;

        if (base.type == EdgeType::NS) {
            const Node& ns_target = graph_.nodes[base.dst];
            const Node& alpha = graph_.nodes[base.src];
            const Zone& current_zone = graph_.zones[alpha.zone];
            const std::string& cut = h.suffix_ref(base.src);

            if (cut == current_zone.origin) return false;

            auto sit = graph_.server_by_name.find(ns_target.name);
            if (sit == graph_.server_by_name.end()) return false;

            if (graph_.nodes[target].server != sit->second) return false;
            if (graph_.nodes[target].zone == alpha.zone) return false;
            const std::string& ns = h.suffix_ref(target);
            const std::string& raw = h.symbolic_stripped_name_ref(target);
            if (!h.IsBeta(target) && raw == ns_target.name) return false;
            return ns == cut || is_descendant_or_same(ns, cut) ||
                   is_descendant_or_same(raw, cut);
        }

        if (base.type == EdgeType::DNAME) {
            int source = base.dst;
            if (h.IsBeta(target)) return h.betaTargetCompatible(source, target);
            if (h.IsConcrete(target) || h.IsWildcard(target)) {
                return h.dnameTargetNameMatches(source, target);
            }
            return false;
        }

        if (base.type == EdgeType::CNAME) {
            int source = base.dst;
            if (target == source) return false;
            if (h.IsBeta(target)) return h.betaMatches(target, source);
            if (h.IsConcrete(target)) {
                return graph_.nodes[target].name == graph_.nodes[source].name;
            }
            if (h.IsWildcard(target)) return h.wildcardCovers(target, source);
        }
        return false;
    }

    void rebuildDelFor(const Edge& ns_edge,
                       const SemanticHelpers& h,
                       std::vector<int>& added_edges,
                       std::set<int>& affected) {
        const Node& alpha = graph_.nodes[ns_edge.src];
        const Node& ns_target = graph_.nodes[ns_edge.dst];
        const std::string& cut = h.suffix_ref(alpha.id);
        const Zone& current_zone = graph_.zones[alpha.zone];
        if (cut == current_zone.origin) return;

        auto sit = graph_.server_by_name.find(ns_target.name);
        if (sit == graph_.server_by_name.end()) return;

        int target_server = sit->second;

        auto server_it = semantic_index_.del_by_server_cut.find(target_server);
        if (server_it == semantic_index_.del_by_server_cut.end()) return;
        auto owners = server_it->second.find(cut);
        if (owners == server_it->second.end()) return;
        node_candidate_marker_.next();
        for (int nid : owners->second) {
            if (!node_candidate_marker_.mark(nid) ||
                !reach_index_.HasOwnerOutgoing(nid) ||
                !semanticBaseMayInduceToNode(ns_edge, nid, h)) {
                continue;
            }
            addEdge(ns_edge.dst, nid, EdgeType::Del,
                    "induced by " + ns_edge.record, ns_edge.id,
                    added_edges, affected);
        }
    }

    void rebuildDRewFor(const Edge& dname_edge,
                        const SemanticHelpers& h,
                        std::vector<int>& added_edges,
                        std::set<int>& affected) {
        int source = dname_edge.dst;
        const std::string& source_suffix = h.suffix_ref(source);
        node_candidate_marker_.next();
        std::vector<int> candidates;
        appendNodeCandidates(
            semantic_index_.beta_desc_by_suffix,
            source_suffix,
            candidates);
        for (const std::string& ancestor :
             ancestor_suffixes_inclusive(source_suffix)) {
            appendNodeCandidates(
                semantic_index_.beta_by_suffix,
                ancestor,
                candidates);
        }
        appendNodeCandidates(
            semantic_index_.concrete_desc_by_suffix,
            source_suffix,
            candidates);
        appendNodeCandidates(
            semantic_index_.wildcard_desc_by_suffix,
            source_suffix,
            candidates);

        for (int nid : candidates) {
            if (!reach_index_.HasOwnerOutgoing(nid) ||
                !semanticBaseMayInduceToNode(dname_edge, nid, h)) {
                continue;
            }
            addEdge(source, nid, EdgeType::DRew,
                    "induced by " + dname_edge.record, dname_edge.id,
                    added_edges, affected);
        }
    }

    void rebuildCRewFor(const Edge& cname_edge,
                        const SemanticHelpers& h,
                        std::vector<int>& added_edges,
                        std::set<int>& affected) {
        int source = cname_edge.dst;
        const std::string& raw = h.symbolic_stripped_name_ref(source);
        node_candidate_marker_.next();
        std::vector<int> candidates;
        appendNodeCandidates(
            semantic_index_.concrete_by_name,
            graph_.nodes[source].name,
            candidates);
        if (auto parent = immediate_parent_suffix(raw)) {
            appendNodeCandidates(
                semantic_index_.wildcard_by_parent,
                *parent,
                candidates);
        }
        const std::vector<std::string> beta_suffixes =
            h.IsBeta(source) ? ancestor_suffixes_inclusive(raw)
                             : ancestor_suffixes_proper(raw);
        for (const std::string& suffix : beta_suffixes) {
            appendNodeCandidates(
                semantic_index_.beta_by_suffix,
                suffix,
                candidates);
        }

        for (int nid : candidates) {
            if (!reach_index_.HasOwnerOutgoing(nid) ||
                !semanticBaseMayInduceToNode(cname_edge, nid, h)) {
                continue;
            }
            addEdge(source, nid, EdgeType::CRew,
                    "induced by " + cname_edge.record, cname_edge.id,
                    added_edges, affected);
        }
    }

    void collectConservativeAffectedEdges(std::set<int>& affected,
                                          const std::vector<int>& touched_nodes) const {
        std::set<int> touched(touched_nodes.begin(), touched_nodes.end());
        std::set<int> changed_owners;
        std::vector<int> seed_edges(affected.begin(), affected.end());
        auto add_out = [&](int node) {
            auto it = graph_.outgoing_edges.find(node);
            if (it == graph_.outgoing_edges.end()) return;
            for (int out_eid : it->second) affected.insert(out_eid);
        };
        auto add_in_semantic = [&](int node) {
            auto it = incoming_edges_.find(node);
            if (it == incoming_edges_.end()) return;
            for (int in_eid : it->second) {
                if (in_eid < 0 || in_eid >= static_cast<int>(graph_.edges.size())) continue;
                const Edge& e = graph_.edges[in_eid];
                if (is_semantic_type(e.type)) {
                    affected.insert(in_eid);
                }
            }
        };

        for (int eid : seed_edges) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
            const Edge& e = graph_.edges[eid];
            touched.insert(e.src);
            touched.insert(e.dst);
            if (is_base_type(e.type)) changed_owners.insert(e.src);
            add_out(e.src);
            add_out(e.dst);
        }

        for (int nid : touched) {
            add_out(nid);
            add_in_semantic(nid);
        }

        // A changed owner can alter local-cover, beta/wildcard priority, or
        // delegation shadowing.  Recompute only semantic edges in the source
        // server and destination zone contexts that can observe that owner.
        for (int owner : changed_owners) {
            if (owner < 0 || owner >= static_cast<int>(graph_.nodes.size())) continue;
            const Node& node = graph_.nodes[owner];
            auto src_it = semantic_edges_by_src_server_.find(node.server);
            if (src_it != semantic_edges_by_src_server_.end()) {
                affected.insert(src_it->second.begin(), src_it->second.end());
            }
            auto dst_it = semantic_edges_by_dst_context_.find(
                nodeContextKey(node.server, node.zone));
            if (dst_it != semantic_edges_by_dst_context_.end()) {
                affected.insert(dst_it->second.begin(), dst_it->second.end());
            }
            auto org_it = org_edges_by_zone_.find(node.zone);
            if (org_it != org_edges_by_zone_.end()) {
                affected.insert(org_it->second.begin(), org_it->second.end());
            }
        }

        if (!zone_routing_changes_.empty()) {
            SemanticHelpers h(graph_);
            for (const Edge& e : graph_.edges) {
                if (e.deleted ||
                    (e.type != EdgeType::Del &&
                     e.type != EdgeType::DRew &&
                     e.type != EdgeType::CRew)) {
                    continue;
                }
                const int query_node =
                    e.type == EdgeType::CRew ? e.src : e.dst;
                if (query_node < 0 ||
                    query_node >= static_cast<int>(graph_.nodes.size())) {
                    continue;
                }
                const std::string& query_name =
                    h.symbolic_stripped_name_ref(query_node);
                for (const std::string& origin : zone_routing_changes_) {
                    if (is_descendant_or_same(query_name, origin) ||
                        is_descendant_or_same(origin, query_name)) {
                        affected.insert(e.id);
                        break;
                    }
                }
            }
        }
    }

    void recomputeAffectedReach(const std::set<int>& affected, IncrementalResult& result) {
        for (int eid : affected) {
            if (eid < 0 || eid >= static_cast<int>(graph_.edges.size())) continue;
            Edge& e = graph_.edges[eid];
            int old = e.reach;
            int next = reach_index_.ComputeEdgeReach(e);
            e.reach = next;
            if (old == next) continue;
            result.changed_edges.push_back(eid);
            if (old == 1 && next == 0) {
                result.reach_1_to_0.push_back(eid);
            } else if (old == 0 && next == 1) {
                result.reach_0_to_1.push_back(eid);
            }
        }
    }

    void finishIncrementalResult(const std::vector<BugReport>& before,
                                 IncrementalResult& result,
                                 bool compute_full_reports = true,
                                 bool compute_affected_paths = true) {
        using Clock = std::chrono::steady_clock;
        auto elapsed = [](Clock::time_point begin, Clock::time_point end) {
            return std::chrono::duration<double>(end - begin).count();
        };
        const auto local_start = Clock::now();
        result.traversal_starts = collect_traversal_starts(
            result.changed_edges, result.added_edges, result.removed_edges,
            &result.warnings);

        if (compute_affected_paths) {
            PathTraverser traverser(graph_);
            for (int start : result.traversal_starts) {
                std::vector<PathResult> local = traverser.traverseFromNode(start);
                result.affected_paths.insert(result.affected_paths.end(),
                                             local.begin(), local.end());
            }
        }
        result.local_traversal_seconds = elapsed(local_start, Clock::now());

        if (compute_full_reports) {
            const auto refresh_start = Clock::now();
            refreshBugCache();
            result.all_reports_after = bug_cache_;
            diffReports(before, bug_cache_, result.new_reports, result.fixed_reports);
            result.report_refresh_seconds = elapsed(refresh_start, Clock::now());
        }
    }

    void refreshBugCache() {
        PathTraverser traverser(graph_);
        std::vector<PathResult> paths = traverser.traverseAll();
        BugDetector detector(graph_, server_views_complete_);
        bug_cache_ = detector.detectAll(paths);
    }

    static void diffReports(const std::vector<BugReport>& before,
                            const std::vector<BugReport>& after,
                            std::vector<BugReport>& new_reports,
                            std::vector<BugReport>& fixed_reports) {
        std::map<std::string, BugReport> before_map;
        std::map<std::string, BugReport> after_map;
        for (const BugReport& r : before) before_map.emplace(reportKey(r), r);
        for (const BugReport& r : after) after_map.emplace(reportKey(r), r);

        for (const auto& [key, report] : after_map) {
            if (before_map.find(key) == before_map.end()) {
                new_reports.push_back(report);
            }
        }
        for (const auto& [key, report] : before_map) {
            if (after_map.find(key) == after_map.end()) {
                fixed_reports.push_back(report);
            }
        }
    }
};

struct RepairCandidate {
    BugReport bug;
    std::vector<RepairAction> actions;
    int priority = 100;
    std::string risk = "high";
    std::string rationale;
    std::string expected_effect;
    bool valid = false;
    bool introduces_severe_bug = false;
    size_t grouped_reports = 1;
    std::string repair_group_key;
    IncrementalResult validation;
};

static int forward_base_edge_for_repair(const SemanticGraph& graph, int edge_id) {
    std::set<int> seen;
    int current = edge_id;
    while (current >= 0 && current < static_cast<int>(graph.edges.size())) {
        if (!seen.insert(current).second) break;
        const Edge& edge = graph.edges[current];
        if (is_base_type(edge.type)) return current;
        auto origin = graph.semantic_edge_origin.find(current);
        if (origin == graph.semantic_edge_origin.end()) break;
        current = origin->second;
    }
    return -1;
}

static std::string repair_base_edge_key(const SemanticGraph& graph, int edge_id) {
    if (edge_id < 0 || edge_id >= static_cast<int>(graph.edges.size())) return "";
    const Edge& edge = graph.edges[edge_id];
    if (edge.deleted || !is_base_type(edge.type) ||
        edge.src < 0 || edge.dst < 0 ||
        edge.src >= static_cast<int>(graph.nodes.size()) ||
        edge.dst >= static_cast<int>(graph.nodes.size())) {
        return "";
    }

    SemanticHelpers helpers(graph);
    const Node& src = graph.nodes[edge.src];
    const Node& dst = graph.nodes[edge.dst];
    std::string owner = src.name;
    std::string rdata = dst.name;
    if (edge.type == EdgeType::NS) {
        owner = helpers.suffix_ref(src.id);
    } else if (edge.type == EdgeType::DNAME) {
        owner = helpers.suffix_ref(src.id);
        rdata = helpers.suffix_ref(dst.id);
    }

    std::ostringstream out;
    out << graph.servers[src.server].name << "|"
        << graph.zones[src.zone].origin << "|"
        << owner << "|"
        << edge_type_name(edge.type) << "|"
        << rdata;
    return out.str();
}

static int stale_report_base_edge(const SemanticGraph& graph, const BugReport& bug) {
    for (int edge_id : bug.path) {
        const int base = forward_base_edge_for_repair(graph, edge_id);
        if (base >= 0 && base < static_cast<int>(graph.edges.size()) &&
            is_base_type(graph.edges[base].type)) {
            return base;
        }
    }
    return -1;
}

static std::vector<int> stale_blocking_base_edges(const SemanticGraph& graph,
                                                  const BugReport& bug) {
    const int stale_base = stale_report_base_edge(graph, bug);
    if (stale_base < 0 || stale_base >= static_cast<int>(graph.edges.size())) return {};
    const Edge& stale_edge = graph.edges[stale_base];
    if (stale_edge.src < 0 ||
        stale_edge.src >= static_cast<int>(graph.nodes.size())) {
        return {};
    }

    const int owner_id = stale_edge.src;
    std::set<int> blockers;
    SemanticHelpers helpers(graph);
    const Node& owner = graph.nodes[owner_id];
    const std::string& owner_name = helpers.symbolic_stripped_name_ref(owner_id);
    const bool dname_shadow =
        bug.reason.find("DNAME") != std::string::npos;

    if (!dname_shadow) {
        for (const Edge& edge : graph.edges) {
            if (edge.deleted || edge.dst != owner_id || edge.reach != 0) continue;
            if (edge.type != EdgeType::Del &&
                edge.type != EdgeType::CRew &&
                edge.type != EdgeType::DRew) {
                continue;
            }
            const int base = forward_base_edge_for_repair(graph, edge.id);
            if (base >= 0 && base != stale_base &&
                base < static_cast<int>(graph.edges.size()) &&
                is_base_type(graph.edges[base].type)) {
                blockers.insert(base);
            }
        }
    }

    // Keep only the closest ancestor DNAME: it is the record selected by
    // authoritative matching and is therefore the immediate blocker.
    size_t closest_dname_length = 0;
    std::vector<int> closest_dnames;
    for (const Edge& edge : graph.edges) {
        if (edge.deleted || edge.type != EdgeType::DNAME ||
            edge.id == stale_base || edge.src < 0 ||
            edge.src >= static_cast<int>(graph.nodes.size())) {
            continue;
        }
        const Node& dname_owner = graph.nodes[edge.src];
        if (dname_owner.zone != owner.zone) continue;
        const std::string& dname_name = helpers.suffix_ref(edge.src);
        if (!is_strict_descendant_of(owner_name, dname_name)) continue;
        if (dname_name.size() > closest_dname_length) {
            closest_dname_length = dname_name.size();
            closest_dnames.clear();
        }
        if (dname_name.size() == closest_dname_length) {
            closest_dnames.push_back(edge.id);
        }
    }
    if (dname_shadow) {
        blockers.clear();
        blockers.insert(closest_dnames.begin(), closest_dnames.end());
    }

    // Generic r=0 incoming edges can be origin edges without a base-record
    // origin. Infer NS shadowing from the closest zone cut in the same zone.
    if (!dname_shadow) {
        size_t closest_cut_length = 0;
        std::vector<int> closest_ns_records;
        for (const Edge& edge : graph.edges) {
            if (edge.deleted || edge.type != EdgeType::NS ||
                edge.src < 0 || edge.src >= static_cast<int>(graph.nodes.size())) {
                continue;
            }
            const Node& ns_owner = graph.nodes[edge.src];
            if (ns_owner.zone != owner.zone) continue;
            const std::string& cut = helpers.suffix_ref(edge.src);
            if (cut == graph.zones[owner.zone].origin) continue;
            if (!is_strict_descendant_of(owner_name, cut)) continue;
            if (cut.size() > closest_cut_length) {
                closest_cut_length = cut.size();
                closest_ns_records.clear();
            }
            if (cut.size() == closest_cut_length) {
                closest_ns_records.push_back(edge.id);
            }
        }
        blockers.insert(closest_ns_records.begin(), closest_ns_records.end());
    }

    return std::vector<int>(blockers.begin(), blockers.end());
}

static std::string stale_repair_root_component(const SemanticGraph& graph,
                                               const BugReport& bug) {
    std::set<std::string> blocker_keys;
    for (int edge_id : stale_blocking_base_edges(graph, bug)) {
        const std::string key = repair_base_edge_key(graph, edge_id);
        if (!key.empty()) blocker_keys.insert(key);
    }
    if (!blocker_keys.empty()) {
        std::ostringstream out;
        out << "blockers=";
        bool first = true;
        for (const std::string& key : blocker_keys) {
            if (!first) out << ";";
            first = false;
            out << key;
        }
        return out.str();
    }

    const int stale_base = stale_report_base_edge(graph, bug);
    const std::string record_key = repair_base_edge_key(graph, stale_base);
    if (!record_key.empty()) return "record=" + record_key;

    std::ostringstream fallback;
    fallback << "record="
             << bug.server.value_or("") << "|"
             << bug.zone.value_or("") << "|"
             << bug.startName.value_or("") << "|"
             << bug.query.value_or("");
    return fallback.str();
}

class RepairCandidateGenerator {
public:
    explicit RepairCandidateGenerator(const SemanticGraph& graph,
                                      const std::vector<BugReport>& baseline_reports,
                                      bool di_is_severe = false)
        : graph_(graph),
          helpers_(graph),
          baseline_reports_(baseline_reports),
          di_is_severe_(di_is_severe) {}

    std::vector<RepairCandidate> generateAndValidate(const BugReport& bug) const {
        std::vector<RepairCandidate> candidates = generate(bug);
        candidates = dedupeCandidates(std::move(candidates));

        std::vector<RepairCandidate> valid;
        for (RepairCandidate candidate : candidates) {
            candidate.validation = lightweightValidateActions(candidate.actions);

            bool fixed = candidateLikelyFixesBug(candidate, bug);
            candidate.introduces_severe_bug = false;
            candidate.valid = fixed && !candidate.introduces_severe_bug;
            if (candidate.valid) {
                valid.push_back(std::move(candidate));
            }
        }

        rankCandidates(valid);
        return valid;
    }

private:
    struct DelegationSnapshot {
        int parent_zone = -1;
        int child_zone = -1;
        std::set<std::string> parent_ns;
        std::set<std::string> child_ns;
        std::map<std::string, std::set<std::pair<EdgeType, std::string>>> parent_addr;
        std::map<std::string, std::set<std::pair<EdgeType, std::string>>> child_addr;
    };

    const SemanticGraph& graph_;
    SemanticHelpers helpers_;
    const std::vector<BugReport>& baseline_reports_;
    bool di_is_severe_ = false;

    static std::string bugKey(const BugReport& report) {
        std::ostringstream key;
        key << report.kind << "|"
            << report.zoneCut.value_or("") << "|"
            << report.nameserver.value_or("") << "|"
            << report.startName.value_or("") << "|"
            << report.query.value_or("") << "|"
            << report.rewrittenName.value_or("") << "|"
            << report.server.value_or("") << "|"
            << report.zone.value_or("") << "|"
            << report.reason;
        return key.str();
    }

    static std::string actionOpName(RepairOp op) {
        if (op == RepairOp::ADD) return "ADD";
        if (op == RepairOp::DELETE) return "DELETE";
        return "MODIFY";
    }

    static std::string recordKey(const RecordInput& r) {
        std::ostringstream out;
        out << normalize_domain(r.server) << "|"
            << normalize_domain(r.zone) << "|"
            << normalize_domain(r.owner) << "|"
            << edge_type_name(r.type) << "|"
            << r.rdata;
        return out.str();
    }

    static std::string actionKey(const RepairAction& a) {
        std::ostringstream out;
        out << actionOpName(a.op) << "|";
        if (a.old_record.has_value()) out << "old=" << recordKey(*a.old_record);
        if (a.new_record.has_value()) out << "|new=" << recordKey(*a.new_record);
        return out.str();
    }

    static std::string candidateKey(const RepairCandidate& c) {
        std::ostringstream out;
        for (const RepairAction& a : c.actions) {
            out << actionKey(a) << ";";
        }
        return out.str();
    }

    bool candidateLikelyFixesBug(const RepairCandidate& candidate,
                                 const BugReport& bug) const {
        for (const RepairAction& action : candidate.actions) {
            if (bug.kind == "RB") {
                if (bug.rewrittenName.has_value() &&
                    action.op == RepairOp::ADD &&
                    action.new_record.has_value() &&
                    (action.new_record->type == EdgeType::A ||
                     action.new_record->type == EdgeType::AAAA) &&
                    normalize_domain(action.new_record->owner) ==
                        normalize_domain(*bug.rewrittenName)) {
                    return true;
                }
                if (actionTouchesRewritePath(action, bug.path)) return true;
                if (bug.startName.has_value() &&
                    action.op == RepairOp::ADD &&
                    action.new_record.has_value() &&
                    normalize_domain(action.new_record->owner) ==
                        normalize_domain(*bug.startName)) {
                    return true;
                }
            } else if (bug.kind == "RL" || bug.kind == "ML") {
                if (actionTouchesRewritePath(action, bug.path)) return true;
                if (action.op == RepairOp::ADD &&
                    action.new_record.has_value() &&
                    (action.new_record->type == EdgeType::A ||
                     action.new_record->type == EdgeType::AAAA)) {
                    for (int eid : bug.path) {
                        auto rec = originBaseRecord(eid);
                        if (!rec.has_value() || rec->type != EdgeType::CNAME) continue;
                        if (normalize_domain(rec->rdata) ==
                            normalize_domain(action.new_record->owner)) {
                            return true;
                        }
                    }
                }
            } else if (bug.kind == "MG") {
                if (bug.nameserver.has_value() &&
                    action.op == RepairOp::ADD &&
                    action.new_record.has_value() &&
                    (action.new_record->type == EdgeType::A ||
                     action.new_record->type == EdgeType::AAAA) &&
                    normalize_domain(action.new_record->owner) ==
                        normalize_domain(*bug.nameserver)) {
                    return true;
                }
                if (action.op == RepairOp::MODIFY || action.op == RepairOp::DELETE) {
                    return true;
                }
            } else {
                if (!candidate.actions.empty()) return true;
            }
        }
        return false;
    }

    IncrementalResult lightweightValidateActions(const std::vector<RepairAction>& actions) const {
        IncrementalResult result;
        std::set<int> starts;
        for (const RepairAction& action : actions) {
            if (action.op == RepairOp::ADD && action.new_record.has_value()) {
                auto start = findExistingOwnerNode(*action.new_record);
                if (start.has_value()) starts.insert(*start);
            } else if (action.op == RepairOp::DELETE && action.old_record.has_value()) {
                auto start = findExistingOwnerNode(*action.old_record);
                if (start.has_value()) starts.insert(*start);
            } else if (action.op == RepairOp::MODIFY) {
                if (action.old_record.has_value()) {
                    auto start = findExistingOwnerNode(*action.old_record);
                    if (start.has_value()) starts.insert(*start);
                }
                if (action.new_record.has_value()) {
                    auto start = findExistingOwnerNode(*action.new_record);
                    if (start.has_value()) starts.insert(*start);
                }
            }
        }
        result.traversal_starts.assign(starts.begin(), starts.end());
        return result;
    }

    std::optional<int> findExistingOwnerNode(const RecordInput& raw) const {
        RecordInput r = raw;
        r.server = normalize_domain(r.server);
        r.zone = normalize_domain(r.zone);
        r.owner = normalize_domain(r.owner);
        std::string owner = r.owner;
        if (r.type == EdgeType::NS) owner = alpha_name(r.owner);
        if (r.type == EdgeType::DNAME) owner = beta_name(r.owner);

        for (const Zone& z : graph_.zones) {
            if (z.origin != r.zone) continue;
            if (graph_.servers[z.server].name != r.server) continue;
            auto it = z.node_by_name.find(owner);
            if (it != z.node_by_name.end()) return it->second;
        }
        return std::nullopt;
    }

    std::optional<int> findBaseRecordId(const RecordInput& record) const {
        for (const Edge& e : graph_.edges) {
            if (e.deleted || !is_base_type(e.type) || e.type != record.type) continue;
            RecordInput rec = edgeToRecord(e);
            if (recordKey(rec) == recordKey(record)) return e.id;
        }
        return std::nullopt;
    }

    bool actionTouchesRewritePath(const RepairAction& action,
                                  const std::vector<int>& path) const {
        auto record_matches_path = [&](const RecordInput& record) {
            for (int eid : path) {
                auto rec = originBaseRecord(eid);
                if (!rec.has_value()) continue;
                if (recordKey(*rec) == recordKey(record)) return true;
            }
            return false;
        };
        if (action.old_record.has_value() && record_matches_path(*action.old_record)) {
            return true;
        }
        if (action.new_record.has_value() && record_matches_path(*action.new_record)) {
            return true;
        }
        return false;
    }

    std::vector<RepairCandidate> generate(const BugReport& bug) const {
        if (bug.kind == "MG") return generate_for_MG(bug);
        if (bug.kind == "DI") return generate_for_DI(bug);
        if (bug.kind == "LD") return generate_for_LD(bug);
        if (bug.kind == "CZD") return generate_for_CZD(bug);
        if (bug.kind == "RL") return generate_for_RL(bug);
        if (bug.kind == "RB") return generate_for_RB(bug);
        if (bug.kind == "ML") return generate_for_ML(bug);
        if (bug.kind == "STALE") return generate_for_STALE(bug);
        return {};
    }

    std::vector<RepairCandidate> generate_for_MG(const BugReport& bug) const {
        std::vector<RepairCandidate> out;
        if (!bug.zoneCut.has_value() || !bug.nameserver.has_value()) return out;

        const std::string cut = *bug.zoneCut;
        const std::string ns = *bug.nameserver;
        auto parent_zone = findZoneByOriginAndOptionalServer(
            bug.zone.value_or(""), bug.server.value_or(""));
        if (!parent_zone.has_value()) parent_zone = findParentZoneForCut(cut);
        if (!parent_zone.has_value()) return out;

        std::set<std::pair<EdgeType, std::string>> child_addr = findAddressesForNameInZone(cut, ns);
        if (child_addr.empty()) {
            child_addr.insert({EdgeType::A, "<TODO_IP>"});
            child_addr.insert({EdgeType::AAAA, "<TODO_IPV6>"});
        }

        for (const auto& [type, addr] : child_addr) {
            RepairCandidate c = baseCandidate(bug, 1, "low",
                "in-bailiwick delegated nameserver lacks parent-side glue",
                "parent resolver can reach delegated nameserver");
            c.actions.push_back(addAction(zoneServerName(*parent_zone),
                                          graph_.zones[*parent_zone].origin,
                                          ns, type, addr,
                                          "add missing parent-side glue"));
            out.push_back(std::move(c));
        }

        if (auto replacement = findOutOfBailiwickNameserver(cut)) {
            RepairCandidate c = baseCandidate(bug, 4, "medium",
                "change delegation to an out-of-bailiwick nameserver",
                "parent-side glue is no longer required for this delegation");
            c.actions.push_back(modifyAction(zoneServerName(*parent_zone),
                                             graph_.zones[*parent_zone].origin,
                                             cut, EdgeType::NS, ns,
                                             cut, EdgeType::NS, *replacement,
                                             "modify NS target to an out-of-bailiwick server"));
            out.push_back(std::move(c));
        }

        RepairCandidate del = baseCandidate(bug, 10, "high",
            "delete the parent-side NS delegation as a last resort",
            "the missing-glue delegation is removed");
        del.actions.push_back(deleteAction(zoneServerName(*parent_zone),
                                           graph_.zones[*parent_zone].origin,
                                           cut, EdgeType::NS, ns,
                                           "delete NS delegation"));
        out.push_back(std::move(del));
        return out;
    }

    std::vector<RepairCandidate> generate_for_DI(const BugReport& bug) const {
        std::vector<RepairCandidate> out;
        if (!bug.zoneCut.has_value()) return out;

        const std::string cut = *bug.zoneCut;
        DelegationSnapshot view = snapshotDelegation(cut);
        if (view.parent_zone < 0 && bug.zone.has_value()) {
            auto z = findZoneByOriginAndOptionalServer(*bug.zone, bug.server.value_or(""));
            if (z.has_value()) view.parent_zone = *z;
        }
        if (view.parent_zone < 0) return out;

        const std::string parent_server = zoneServerName(view.parent_zone);
        const std::string parent_zone = graph_.zones[view.parent_zone].origin;

        if (view.child_zone >= 0) {
            const std::string child_server = zoneServerName(view.child_zone);
            const std::string child_zone = graph_.zones[view.child_zone].origin;
            for (const std::string& ns : setDifference(view.parent_ns, view.child_ns)) {
                RepairCandidate c = baseCandidate(bug, 1, "low",
                    "child-side NS is missing a parent-side nameserver",
                    "child authoritative NS set matches parent delegation");
                c.actions.push_back(addAction(child_server, child_zone, cut, EdgeType::NS, ns,
                                              "add missing child-side NS"));
                out.push_back(std::move(c));
            }
            for (const std::string& ns : setDifference(view.child_ns, view.parent_ns)) {
                RepairCandidate c = baseCandidate(bug, 3, "medium",
                    "parent-side NS is missing a child-side nameserver",
                    "parent delegation matches child authoritative NS set");
                c.actions.push_back(addAction(parent_server, parent_zone, cut, EdgeType::NS, ns,
                                              "add missing parent-side NS"));
                out.push_back(std::move(c));
            }
        }

        for (const std::string& ns : view.parent_ns) {
            const auto paddr = mapLookup(view.parent_addr, ns);
            const auto caddr = mapLookup(view.child_addr, ns);
            if (paddr == caddr) continue;

            if (!caddr.empty()) {
                for (const auto& addr : caddr) {
                    RepairCandidate c = baseCandidate(bug, 2, "low",
                        "parent-side glue differs from child-side address",
                        "parent glue matches child-side address");
                    for (const auto& old_addr : paddr) {
                        c.actions.push_back(modifyAction(parent_server, parent_zone,
                                                         ns, old_addr.first, old_addr.second,
                                                         ns, addr.first, addr.second,
                                                         "modify parent glue to match child address"));
                    }
                    if (paddr.empty()) {
                        c.actions.push_back(addAction(parent_server, parent_zone,
                                                      ns, addr.first, addr.second,
                                                      "add missing parent glue from child address"));
                    }
                    out.push_back(std::move(c));
                }
            }
        }

        for (const std::string& ns : setDifference(view.parent_ns, view.child_ns)) {
            RepairCandidate c = baseCandidate(bug, 8, "high",
                "delete parent-side NS that child side does not list",
                "parent and child NS sets move closer together");
            c.actions.push_back(deleteAction(parent_server, parent_zone, cut, EdgeType::NS, ns,
                                            "delete extra parent-side NS"));
            out.push_back(std::move(c));
        }
        return out;
    }

    std::vector<RepairCandidate> generate_for_LD(const BugReport& bug) const {
        std::vector<RepairCandidate> out;
        if (!bug.zoneCut.has_value() || !bug.nameserver.has_value()) return out;

        const std::string cut = *bug.zoneCut;
        const std::string ns = *bug.nameserver;
        auto parent_zone = findParentZoneForCut(cut);

        RepairCandidate add_zone = baseCandidate(bug, 3, "medium",
            "delegated nameserver exists but does not host the child zone",
            "server gains a child-zone authoritative apex NS");
        add_zone.actions.push_back(addAction(ns, cut, cut, EdgeType::NS, ns,
                                             "add child-zone apex NS to delegated server"));
        add_zone.actions.push_back(addAction(ns, cut, ns, EdgeType::A, "<TODO_IP>",
                                             "add nameserver address if missing"));
        out.push_back(std::move(add_zone));

        if (parent_zone.has_value()) {
            if (auto host = findServerHostingZone(cut)) {
                RepairCandidate mod = baseCandidate(bug, 3, "medium",
                    "delegate to a server that already hosts the child zone",
                    "parent delegation points at an authoritative server");
                mod.actions.push_back(modifyAction(zoneServerName(*parent_zone),
                                                   graph_.zones[*parent_zone].origin,
                                                   cut, EdgeType::NS, ns,
                                                   cut, EdgeType::NS, *host,
                                                   "modify parent-side NS to authoritative server"));
                out.push_back(std::move(mod));
            }

            RepairCandidate del = baseCandidate(bug, 10, "high",
                "delete lame parent-side delegation",
                "lame delegation edge is removed");
            del.actions.push_back(deleteAction(zoneServerName(*parent_zone),
                                               graph_.zones[*parent_zone].origin,
                                               cut, EdgeType::NS, ns,
                                               "delete lame NS delegation"));
            out.push_back(std::move(del));
        }

        return out;
    }

    std::vector<RepairCandidate> generate_for_RB(const BugReport& bug) const {
        std::vector<RepairCandidate> out;
        if (!bug.rewrittenName.has_value()) return out;

        const std::string target = *bug.rewrittenName;
        auto target_zone = findKnownZoneForName(target);
        if (target_zone.has_value()) {
            RepairCandidate add_a = baseCandidate(bug, 1, "low",
                "rewritten target is in a known zone but lacks A/AAAA",
                "target can terminate with an address answer");
            add_a.actions.push_back(addAction(zoneServerName(*target_zone),
                                              graph_.zones[*target_zone].origin,
                                              target, EdgeType::A, "<TODO_IP>",
                                              "add target A record"));
            out.push_back(std::move(add_a));
        }

        if (auto rewrite = lastBaseRewriteRecord(bug.path)) {
            if (auto safe = findSafeRewriteTarget(*rewrite, bug)) {
                RepairCandidate mod = baseCandidate(bug, 2, "medium",
                    "change last rewrite target to an addressable name",
                    "rewrite chain terminates at an existing addressable owner");
                RecordInput old = *rewrite;
                RecordInput neu = old;
                neu.rdata = *safe;
                mod.actions.push_back(modifyRecordAction(old, neu,
                                                         "modify rewrite target to safe addressable name"));
                out.push_back(std::move(mod));
            }

            if (bug.startName.has_value()) {
                RepairCandidate exact = baseCandidate(bug, 3, "medium",
                    "add exact owner record to bypass bad wildcard/rewrite path",
                    "specific query can terminate without following the bad rewrite");
                exact.actions.push_back(addAction(rewrite->server, rewrite->zone,
                                                  *bug.startName, EdgeType::A, "<TODO_IP>",
                                                  "add exact address override"));
                out.push_back(std::move(exact));
            }

            RepairCandidate del = baseCandidate(bug, 8, "high",
                "delete bad rewrite record",
                "blackholing rewrite path is removed");
            del.actions.push_back(deleteRecordAction(*rewrite, "delete bad CNAME/DNAME"));
            out.push_back(std::move(del));
        }

        return out;
    }

    std::vector<RepairCandidate> generate_for_RL(const BugReport& bug) const {
        return generate_for_rewrite_loop_or_length(bug,
                                                   "rewrite loop repeats a query",
                                                   "CNAME/DNAME rewrite loop should disappear",
                                                   false);
    }

    std::vector<RepairCandidate> generate_for_ML(const BugReport& bug) const {
        return generate_for_rewrite_loop_or_length(bug,
                                                   "rewrite produces a name exceeding DNS limits",
                                                   "rewritten name should satisfy DNS length limits",
                                                   true);
    }

    std::vector<RepairCandidate> generate_for_CZD(const BugReport& bug) const {
        std::vector<RepairCandidate> out;
        std::set<std::string> seen;
        for (int eid : bug.path) {
            auto origin = originBaseRecord(eid);
            if (!origin.has_value() || origin->type != EdgeType::NS) continue;
            if (!seen.insert(recordKey(*origin)).second) continue;

            RepairCandidate mod = baseCandidate(bug, 4, "medium",
                "modify an NS delegation involved in the cycle",
                "zone dependency cycle is broken by moving delegation out of cycle");
            RecordInput neu = *origin;
            neu.rdata = "<TODO_OUT_OF_CYCLE_NS>";
            mod.actions.push_back(modifyRecordAction(*origin, neu,
                                                     "modify NS target to break cycle"));
            out.push_back(std::move(mod));

            RepairCandidate del = baseCandidate(bug, 10, "high",
                "delete an NS delegation involved in the cycle",
                "cycle edge is removed");
            del.actions.push_back(deleteRecordAction(*origin, "delete cycle NS delegation"));
            out.push_back(std::move(del));
        }
        return out;
    }

    std::vector<RepairCandidate> generate_for_STALE(const BugReport& bug) const {
        std::vector<RepairCandidate> out;
        const std::string root = stale_repair_root_component(graph_, bug);

        // One blocker can shadow several records. Delete all stale records in
        // that root-cause group so the representative repair fixes the group,
        // rather than only its selected witness.
        std::map<std::string, RecordInput> stale_records;
        for (const BugReport& report : baseline_reports_) {
            if (report.kind != "STALE" ||
                stale_repair_root_component(graph_, report) != root) {
                continue;
            }
            const int edge_id = stale_report_base_edge(graph_, report);
            if (edge_id < 0 || edge_id >= static_cast<int>(graph_.edges.size())) continue;
            const RecordInput record = edgeToRecord(graph_.edges[edge_id]);
            stale_records.emplace(recordKey(record), record);
        }
        if (stale_records.empty()) {
            const int edge_id = stale_report_base_edge(graph_, bug);
            if (edge_id >= 0 && edge_id < static_cast<int>(graph_.edges.size())) {
                const RecordInput record = edgeToRecord(graph_.edges[edge_id]);
                stale_records.emplace(recordKey(record), record);
            }
        }

        if (!stale_records.empty()) {
            RepairCandidate remove_stale = baseCandidate(
                bug, 4, "low",
                "remove records that are unreachable under authoritative matching semantics",
                "all stale-record reports sharing this root cause should disappear without "
                "changing currently reachable resolution paths");
            for (const auto& [_, record] : stale_records) {
                remove_stale.actions.push_back(deleteRecordAction(
                    record, "delete shadowed or otherwise unreachable resource record"));
            }
            out.push_back(std::move(remove_stale));
        }

        std::map<std::string, RecordInput> blocking_records;
        for (int edge_id : stale_blocking_base_edges(graph_, bug)) {
            if (edge_id < 0 || edge_id >= static_cast<int>(graph_.edges.size())) continue;
            const RecordInput record = edgeToRecord(graph_.edges[edge_id]);
            blocking_records.emplace(recordKey(record), record);
        }
        if (!blocking_records.empty()) {
            RepairCandidate remove_blocker = baseCandidate(
                bug, 8, "high",
                "remove the NS/CNAME/DNAME record that blocks otherwise valid records",
                "blocked records should become reachable; validation must reject this candidate "
                "if removing the blocker disrupts valid paths or introduces a severe vulnerability");
            for (const auto& [_, record] : blocking_records) {
                remove_blocker.actions.push_back(deleteRecordAction(
                    record, "remove blocking record and reactivate shadowed records"));
            }
            out.push_back(std::move(remove_blocker));
        }

        return out;
    }

    std::vector<RepairCandidate> generate_for_rewrite_loop_or_length(const BugReport& bug,
                                                                     const std::string& rationale,
                                                                     const std::string& effect,
                                                                     bool allow_exact_override) const {
        std::vector<RepairCandidate> out;
        std::set<std::string> seen;
        for (int eid : bug.path) {
            auto record = originBaseRecord(eid);
            if (!record.has_value()) continue;
            if (record->type != EdgeType::CNAME && record->type != EdgeType::DNAME) continue;
            if (!seen.insert(recordKey(*record)).second) continue;

            if (record->type == EdgeType::CNAME &&
                record->owner.rfind("*.", 0) == 0 &&
                findKnownZoneForName(record->rdata).has_value()) {
                RepairCandidate exact_target = baseCandidate(bug, 1, "low",
                    "add exact address record for wildcard CNAME target",
                    "exact target owner blocks wildcard CRew and terminates with A/AAAA");
                exact_target.actions.push_back(addAction(record->server, record->zone,
                                                         record->rdata, EdgeType::A, "<TODO_IP>",
                                                         "add exact target A to block wildcard rewrite loop"));
                out.push_back(std::move(exact_target));
            }

            auto safe_target = findSafeRewriteTarget(*record, bug);
            RepairCandidate mod = baseCandidate(
                bug,
                safe_target.has_value() ? 2 : 6,
                "medium",
                safe_target.has_value()
                    ? rationale
                    : rationale + "; no concrete safe target was found automatically",
                effect);
            RecordInput neu = *record;
            neu.rdata = safe_target.value_or(
                allow_exact_override ? "<TODO_SHORT_TARGET>" : "<TODO_SAFE_TARGET>");
            mod.actions.push_back(modifyRecordAction(*record, neu,
                                                     safe_target.has_value()
                                                         ? "modify CNAME/DNAME target"
                                                         : "modify CNAME/DNAME target after user supplies a safe target"));
            out.push_back(std::move(mod));

            if (allow_exact_override && bug.startName.has_value()) {
                RepairCandidate exact = baseCandidate(bug, 3, "medium",
                    "add exact owner record to bypass wildcard/DNAME rewrite",
                    "specific query can terminate before the problematic rewrite");
                exact.actions.push_back(addAction(record->server, record->zone,
                                                  *bug.startName, EdgeType::A, "<TODO_IP>",
                                                  "add exact address override"));
                out.push_back(std::move(exact));
            }

            RepairCandidate del = baseCandidate(bug, 8, "high",
                "delete rewrite record in problematic path",
                "problematic rewrite path is removed");
            del.actions.push_back(deleteRecordAction(*record, "delete CNAME/DNAME"));
            out.push_back(std::move(del));
        }
        return out;
    }

    RepairCandidate baseCandidate(const BugReport& bug,
                                  int priority,
                                  const std::string& risk,
                                  const std::string& rationale,
                                  const std::string& effect) const {
        RepairCandidate c;
        c.bug = bug;
        c.priority = priority;
        c.risk = risk;
        c.rationale = rationale;
        c.expected_effect = effect;
        return c;
    }

    RepairAction addAction(const std::string& server,
                           const std::string& zone,
                           const std::string& owner,
                           EdgeType type,
                           const std::string& rdata,
                           const std::string& rationale) const {
        RepairAction a;
        a.op = RepairOp::ADD;
        a.target_server = server;
        a.target_zone = zone;
        a.new_record = RecordInput{server, zone, owner, type, rdata};
        a.rationale = rationale;
        return a;
    }

    RepairAction deleteAction(const std::string& server,
                              const std::string& zone,
                              const std::string& owner,
                              EdgeType type,
                              const std::string& rdata,
                              const std::string& rationale) const {
        RepairAction a;
        a.op = RepairOp::DELETE;
        a.target_server = server;
        a.target_zone = zone;
        a.old_record = RecordInput{server, zone, owner, type, rdata};
        a.rationale = rationale;
        return a;
    }

    RepairAction modifyAction(const std::string& server,
                              const std::string& zone,
                              const std::string& old_owner,
                              EdgeType old_type,
                              const std::string& old_rdata,
                              const std::string& new_owner,
                              EdgeType new_type,
                              const std::string& new_rdata,
                              const std::string& rationale) const {
        RepairAction a;
        a.op = RepairOp::MODIFY;
        a.target_server = server;
        a.target_zone = zone;
        a.old_record = RecordInput{server, zone, old_owner, old_type, old_rdata};
        a.new_record = RecordInput{server, zone, new_owner, new_type, new_rdata};
        a.rationale = rationale;
        return a;
    }

    RepairAction deleteRecordAction(const RecordInput& record,
                                    const std::string& rationale) const {
        RepairAction a;
        a.op = RepairOp::DELETE;
        a.target_server = record.server;
        a.target_zone = record.zone;
        a.old_record = record;
        a.rationale = rationale;
        return a;
    }

    RepairAction modifyRecordAction(const RecordInput& old_record,
                                    const RecordInput& new_record,
                                    const std::string& rationale) const {
        RepairAction a;
        a.op = RepairOp::MODIFY;
        a.target_server = new_record.server;
        a.target_zone = new_record.zone;
        a.old_record = old_record;
        a.new_record = new_record;
        a.rationale = rationale;
        return a;
    }

    std::optional<RecordInput> originBaseRecord(int edge_id) const {
        int current = edge_id;
        std::set<int> seen;
        while (current >= 0 && current < static_cast<int>(graph_.edges.size())) {
            if (!seen.insert(current).second) return std::nullopt;
            const Edge& e = graph_.edges[current];
            if (is_base_type(e.type)) return edgeToRecord(e);
            auto it = graph_.semantic_edge_origin.find(current);
            if (it == graph_.semantic_edge_origin.end()) return std::nullopt;
            current = it->second;
        }
        return std::nullopt;
    }

    std::optional<RecordInput> lastBaseRewriteRecord(const std::vector<int>& path) const {
        for (auto it = path.rbegin(); it != path.rend(); ++it) {
            auto record = originBaseRecord(*it);
            if (record.has_value() &&
                (record->type == EdgeType::CNAME || record->type == EdgeType::DNAME)) {
                return record;
            }
        }
        return std::nullopt;
    }

    RecordInput edgeToRecord(const Edge& e) const {
        const Node& src = graph_.nodes[e.src];
        const Node& dst = graph_.nodes[e.dst];
        std::string owner = src.name;
        std::string rdata = dst.name;
        if (e.type == EdgeType::NS) {
            owner = helpers_.suffix_ref(src.id);
        } else if (e.type == EdgeType::DNAME) {
            owner = helpers_.suffix_ref(src.id);
            rdata = helpers_.suffix_ref(dst.id);
        }
        return RecordInput{
            graph_.servers[src.server].name,
            graph_.zones[src.zone].origin,
            owner,
            e.type,
            rdata
        };
    }

    std::optional<int> findZoneByOriginAndOptionalServer(const std::string& zone,
                                                         const std::string& server) const {
        for (const Zone& z : graph_.zones) {
            if (z.origin != zone) continue;
            if (!server.empty() && graph_.servers[z.server].name != server) continue;
            return z.id;
        }
        return std::nullopt;
    }

    std::optional<int> findParentZoneForCut(const std::string& cut) const {
        std::optional<int> best;
        size_t best_len = 0;
        for (const Zone& z : graph_.zones) {
            if (z.origin == cut) continue;
            if (!is_strict_descendant_of(cut, z.origin)) continue;
            if (!best.has_value() || z.origin.size() > best_len) {
                best = z.id;
                best_len = z.origin.size();
            }
        }
        return best;
    }

    std::optional<int> findKnownZoneForName(const std::string& name) const {
        std::optional<int> best;
        size_t best_len = 0;
        for (const Zone& z : graph_.zones) {
            if (!is_descendant_or_same(name, z.origin)) continue;
            if (!best.has_value() || z.origin.size() > best_len) {
                best = z.id;
                best_len = z.origin.size();
            }
        }
        return best;
    }

    std::string zoneServerName(int zone) const {
        return graph_.servers[graph_.zones[zone].server].name;
    }

    std::set<std::pair<EdgeType, std::string>> findAddressesForNameInZone(const std::string& zone,
                                                                           const std::string& name) const {
        std::set<std::pair<EdgeType, std::string>> out;
        for (const Zone& z : graph_.zones) {
            if (z.origin != zone) continue;
            auto it = z.node_by_name.find(name);
            if (it == z.node_by_name.end()) continue;
            auto oit = graph_.outgoing_edges.find(it->second);
            if (oit == graph_.outgoing_edges.end()) continue;
            for (int eid : oit->second) {
                const Edge& e = graph_.edges[eid];
                if (e.deleted) continue;
                if (e.type != EdgeType::A && e.type != EdgeType::AAAA) continue;
                out.insert({e.type, graph_.nodes[e.dst].name});
            }
        }
        return out;
    }

    std::optional<std::string> findOutOfBailiwickNameserver(const std::string& cut) const {
        for (const Edge& e : graph_.edges) {
            if (e.deleted || e.type != EdgeType::NS) continue;
            const std::string ns = graph_.nodes[e.dst].name;
            if (!is_descendant_or_same(ns, cut)) return ns;
        }
        return std::nullopt;
    }

    std::optional<std::string> findServerHostingZone(const std::string& zone) const {
        for (const Zone& z : graph_.zones) {
            if (z.origin == zone) return graph_.servers[z.server].name;
        }
        return std::nullopt;
    }

    std::optional<std::string> findAddressableName() const {
        for (const Edge& e : graph_.edges) {
            if (e.deleted) continue;
            if (e.type == EdgeType::A || e.type == EdgeType::AAAA) {
                return graph_.nodes[e.src].name;
            }
        }
        return std::nullopt;
    }

    bool isNameserverOwnerName(const std::string& name) const {
        for (const Edge& e : graph_.edges) {
            if (e.deleted || e.type != EdgeType::NS) continue;
            if (graph_.nodes[e.dst].name == name) return true;
        }
        return false;
    }

    bool isGoodRewriteTargetName(const std::string& name,
                                 const RecordInput& rewrite,
                                 const BugReport& bug) const {
        if (name.empty()) return false;
        if (name == rewrite.owner || name == rewrite.rdata) return false;
        if (bug.startName.has_value() && name == *bug.startName) return false;
        if (bug.rewrittenName.has_value() && name == *bug.rewrittenName) return false;
        if (name.rfind("*.", 0) == 0 ||
            name.rfind(kAlphaPrefix, 0) == 0 ||
            name.rfind(kBetaPrefix, 0) == 0) {
            return false;
        }
        if (isNameserverOwnerName(name)) return false;

        auto z = findKnownZoneForName(name);
        if (!z.has_value()) return false;
        if (graph_.zones[*z].origin == name) return false;

        if (rewrite.type == EdgeType::DNAME) {
            // DNAME targets should be suffixes.  Picking a concrete host with
            // an A record creates beta.host and usually cannot terminate.  Use
            // a known zone suffix instead.
            return graph_.zones[*z].origin == name;
        }
        return true;
    }

    std::optional<std::string> findSafeRewriteTarget(const RecordInput& rewrite,
                                                     const BugReport& bug) const {
        if (rewrite.type == EdgeType::DNAME) {
            // DNAME rdata is a suffix.  Scanning concrete addressable hosts is
            // both semantically wrong and very expensive on large graphs.
            return std::nullopt;
        }

        std::optional<int> preferred_zone;
        if (bug.rewrittenName.has_value()) {
            preferred_zone = findKnownZoneForName(*bug.rewrittenName);
        }
        if (!preferred_zone.has_value()) {
            preferred_zone = findZoneByOriginAndOptionalServer(rewrite.zone, rewrite.server);
        }

        auto scan_zone = [&](int zone) -> std::optional<std::string> {
            if (zone < 0 || zone >= static_cast<int>(graph_.zones.size())) return std::nullopt;
            for (int nid : graph_.zones[zone].nodes) {
                const Node& n = graph_.nodes[nid];
                if (n.kind != NodeKind::Concrete) continue;
                const std::string candidate = n.name;
                if (!isGoodRewriteTargetName(candidate, rewrite, bug)) continue;
                auto oit = graph_.outgoing_edges.find(nid);
                if (oit == graph_.outgoing_edges.end()) continue;
                for (int eid : oit->second) {
                    const Edge& e = graph_.edges[eid];
                    if (!e.deleted && (e.type == EdgeType::A || e.type == EdgeType::AAAA)) {
                        return candidate;
                    }
                }
            }
            return std::nullopt;
        };

        if (preferred_zone.has_value()) {
            if (auto safe = scan_zone(*preferred_zone)) return safe;
        }

        for (const Zone& z : graph_.zones) {
            if (preferred_zone.has_value() && z.id == *preferred_zone) continue;
            if (auto safe = scan_zone(z.id)) return safe;
        }

        return std::nullopt;
    }

    DelegationSnapshot snapshotDelegation(const std::string& cut) const {
        DelegationSnapshot view;
        for (const Edge& e : graph_.edges) {
            if (e.deleted || e.type != EdgeType::NS) continue;
            if (!helpers_.IsAlpha(e.src)) continue;
            if (helpers_.suffix_ref(e.src) != cut) continue;
            const Node& src = graph_.nodes[e.src];
            const std::string ns = graph_.nodes[e.dst].name;
            if (graph_.zones[src.zone].origin == cut) {
                view.child_zone = src.zone;
                view.child_ns.insert(ns);
            } else {
                view.parent_zone = src.zone;
                view.parent_ns.insert(ns);
            }
        }

        if (view.parent_zone >= 0) {
            for (const std::string& ns : view.parent_ns) {
                view.parent_addr[ns] = findAddressesForNameInSpecificZone(view.parent_zone, ns);
            }
        }
        if (view.child_zone >= 0) {
            for (const std::string& ns : view.child_ns) {
                view.child_addr[ns] = findAddressesForNameInSpecificZone(view.child_zone, ns);
            }
        }
        return view;
    }

    std::set<std::pair<EdgeType, std::string>> findAddressesForNameInSpecificZone(int zone,
                                                                                   const std::string& name) const {
        std::set<std::pair<EdgeType, std::string>> out;
        if (zone < 0 || zone >= static_cast<int>(graph_.zones.size())) return out;
        auto it = graph_.zones[zone].node_by_name.find(name);
        if (it == graph_.zones[zone].node_by_name.end()) return out;
        auto oit = graph_.outgoing_edges.find(it->second);
        if (oit == graph_.outgoing_edges.end()) return out;
        for (int eid : oit->second) {
            const Edge& e = graph_.edges[eid];
            if (e.deleted) continue;
            if (e.type == EdgeType::A || e.type == EdgeType::AAAA) {
                out.insert({e.type, graph_.nodes[e.dst].name});
            }
        }
        return out;
    }

    static std::set<std::string> setDifference(const std::set<std::string>& a,
                                               const std::set<std::string>& b) {
        std::set<std::string> out;
        std::set_difference(a.begin(), a.end(), b.begin(), b.end(),
                            std::inserter(out, out.begin()));
        return out;
    }

    static std::set<std::pair<EdgeType, std::string>> mapLookup(
        const std::map<std::string, std::set<std::pair<EdgeType, std::string>>>& m,
        const std::string& key) {
        auto it = m.find(key);
        if (it == m.end()) return {};
        return it->second;
    }

    bool introducesSevereBug(const std::vector<BugReport>& reports,
                             const std::string& original_key) const {
        for (const BugReport& report : reports) {
            if (bugKey(report) == original_key) continue;
            if (report.kind == "DI" && !di_is_severe_) continue;
            if (report.kind == "LD" || report.kind == "MG" ||
                report.kind == "CZD" || report.kind == "RL" ||
                report.kind == "RB" || report.kind == "ML" ||
                (report.kind == "DI" && di_is_severe_)) {
                return true;
            }
        }
        return false;
    }

    static int riskRank(const std::string& risk) {
        if (risk == "low") return 0;
        if (risk == "medium") return 1;
        return 2;
    }

    static bool highImpactAction(const RepairAction& action) {
        auto high = [](const RecordInput& r) {
            return r.type == EdgeType::NS ||
                   r.type == EdgeType::DNAME ||
                   r.owner.rfind("*.", 0) == 0;
        };
        return (action.old_record.has_value() && high(*action.old_record)) ||
               (action.new_record.has_value() && high(*action.new_record));
    }

    static void rankCandidates(std::vector<RepairCandidate>& candidates) {
        std::sort(candidates.begin(), candidates.end(),
                  [](const RepairCandidate& a, const RepairCandidate& b) {
                      if (a.valid != b.valid) return a.valid > b.valid;
                      if (a.introduces_severe_bug != b.introduces_severe_bug) {
                          return !a.introduces_severe_bug;
                      }
                      if (riskRank(a.risk) != riskRank(b.risk)) {
                          return riskRank(a.risk) < riskRank(b.risk);
                      }
                      if (a.priority != b.priority) return a.priority < b.priority;
                      if (a.actions.size() != b.actions.size()) {
                          return a.actions.size() < b.actions.size();
                      }
                      if (a.validation.affected_paths.size() != b.validation.affected_paths.size()) {
                          return a.validation.affected_paths.size() <
                                 b.validation.affected_paths.size();
                      }
                      bool ah = std::any_of(a.actions.begin(), a.actions.end(), highImpactAction);
                      bool bh = std::any_of(b.actions.begin(), b.actions.end(), highImpactAction);
                      if (ah != bh) return !ah;
                      return candidateKey(a) < candidateKey(b);
                  });
    }

    static std::vector<RepairCandidate> dedupeCandidates(std::vector<RepairCandidate> candidates) {
        std::vector<RepairCandidate> out;
        std::set<std::string> seen;
        for (RepairCandidate& c : candidates) {
            if (c.actions.empty()) continue;
            if (seen.insert(candidateKey(c)).second) {
                out.push_back(std::move(c));
            }
        }
        return out;
    }
};

static void print_edges(const SemanticGraph& graph, std::ostream& out) {
    out << "=== Edges ===\n";
    for (const Edge& e : graph.edges) {
        if (e.deleted || e.reach != 1) continue;
        const Node& s = graph.nodes[e.src];
        const Node& d = graph.nodes[e.dst];
        if (s.kind == NodeKind::Origin) {
            out << "[graph] " << s.name << " --" << edge_type_name(e.type)
                << " reach=1--> " << d.name;
            if (d.server >= 0 && d.zone >= 0) {
                out << " [dst " << graph.servers[d.server].name
                    << " " << graph.zones[d.zone].origin << "]";
            }
            out << "\n";
            continue;
        }
        const Server& server = graph.servers[s.server];
        const Zone& zone = graph.zones[s.zone];
        out << "[" << server.name << " " << zone.origin << "] "
            << s.name << " --" << edge_type_name(e.type)
            << " reach=" << e.reach;
        out << "--> " << d.name;
        if (s.server != d.server || s.zone != d.zone) {
            out << " [dst " << graph.servers[d.server].name
                << " " << graph.zones[d.zone].origin << "]";
        }
        out << "\n";
    }
}

static void print_paths(const SemanticGraph& graph,
                        const std::vector<PathResult>& paths,
                        std::ostream& out) {
    out << "\n=== DFS Paths ===\n";
    int idx = 1;
    for (const PathResult& p : paths) {
        out << "Path " << idx++ << ": start=" << graph.nodes[p.start_alpha].name
            << " final=" << p.final_result
            << " reason=" << p.reason << "\n";
        out << "  bindings:";
        if (p.bindings.empty()) {
            out << " <none>";
        } else {
            for (const auto& kv : p.bindings) {
                out << " " << kv.first << "=" << kv.second;
            }
        }
        out << "\n";
        if (p.edges.empty()) {
            out << "  edges: <none>\n";
        } else {
            for (int eid : p.edges) {
                const Edge& e = graph.edges[eid];
                const Node& s = graph.nodes[e.src];
                const Node& d = graph.nodes[e.dst];
                out << "  " << s.name << " --" << edge_type_name(e.type)
                    << "/reach=" << e.reach << "--> " << d.name;
                if (s.server != d.server || s.zone != d.zone) {
                    out << " [dst " << graph.servers[d.server].name
                        << " " << graph.zones[d.zone].origin << "]";
                }
                out << "\n";
            }
        }
    }
}

struct CanonicalSetDigest {
    size_t count = 0;
    std::string digest;
};

struct GraphStateDigest {
    size_t active_edges = 0;
    size_t reachable_edges = 0;
    CanonicalSetDigest active_edge_set;
    CanonicalSetDigest edge_set;
    CanonicalSetDigest path_set;
    CanonicalSetDigest terminal_state_set;
    CanonicalSetDigest report_set;
};

static void append_canonical_field(std::ostringstream& out,
                                   const std::string& value) {
    out << value.size() << ":" << value;
}

static std::string canonical_node_key(const SemanticGraph& graph, int node_id) {
    if (node_id < 0 || node_id >= static_cast<int>(graph.nodes.size())) {
        return "<invalid-node>";
    }
    const Node& node = graph.nodes[node_id];
    std::ostringstream out;
    const std::string server =
        node.server >= 0 && node.server < static_cast<int>(graph.servers.size())
            ? graph.servers[node.server].name
            : "";
    const std::string zone =
        node.zone >= 0 && node.zone < static_cast<int>(graph.zones.size())
            ? graph.zones[node.zone].origin
            : "";
    append_canonical_field(out, server);
    append_canonical_field(out, zone);
    out << static_cast<int>(node.kind) << ":";
    append_canonical_field(out, node.name);
    return out.str();
}

static std::string canonical_edge_key(const SemanticGraph& graph, int edge_id) {
    if (edge_id < 0 || edge_id >= static_cast<int>(graph.edges.size())) {
        return "<invalid-edge>";
    }
    const Edge& edge = graph.edges[edge_id];
    std::ostringstream out;
    append_canonical_field(out, canonical_node_key(graph, edge.src));
    append_canonical_field(out, edge_type_name(edge.type));
    append_canonical_field(out, canonical_node_key(graph, edge.dst));
    out << edge.reach << ":" << (edge.forced_unreachable ? 1 : 0) << ":";
    append_canonical_field(out, edge.record);

    auto origin = graph.semantic_edge_origin.find(edge_id);
    if (origin != graph.semantic_edge_origin.end() &&
        origin->second >= 0 &&
        origin->second < static_cast<int>(graph.edges.size())) {
        const Edge& base = graph.edges[origin->second];
        append_canonical_field(out, canonical_node_key(graph, base.src));
        append_canonical_field(out, edge_type_name(base.type));
        append_canonical_field(out, canonical_node_key(graph, base.dst));
        append_canonical_field(out, base.record);
    } else {
        append_canonical_field(out, "");
    }
    return out.str();
}

static CanonicalSetDigest canonical_set_digest(std::vector<std::string> items) {
    std::sort(items.begin(), items.end());
    items.erase(std::unique(items.begin(), items.end()), items.end());

    uint64_t first = 14695981039346656037ULL;
    uint64_t second = 7809847782465536322ULL;
    auto update = [](uint64_t& hash, uint8_t byte, uint64_t prime) {
        hash ^= byte;
        hash *= prime;
    };
    for (const std::string& item : items) {
        uint64_t length = static_cast<uint64_t>(item.size());
        for (unsigned shift = 0; shift < 64; shift += 8) {
            const uint8_t byte = static_cast<uint8_t>((length >> shift) & 0xffU);
            update(first, byte, 1099511628211ULL);
            update(second, static_cast<uint8_t>(byte ^ 0xa5U),
                   14029467366897019727ULL);
        }
        for (unsigned char byte : item) {
            update(first, byte, 1099511628211ULL);
            update(second, static_cast<uint8_t>(byte ^ 0x5aU),
                   14029467366897019727ULL);
        }
    }

    std::ostringstream digest;
    digest << std::hex << std::setfill('0')
           << std::setw(16) << first
           << std::setw(16) << second;
    return CanonicalSetDigest{items.size(), digest.str()};
}

static std::string canonical_path_key(const SemanticGraph& graph,
                                      const PathResult& path) {
    std::ostringstream out;
    append_canonical_field(out, canonical_node_key(graph, path.start_alpha));
    append_canonical_field(out, canonical_node_key(graph, path.final_node));
    append_canonical_field(out, path.reason);
    append_canonical_field(out, path.final_query);
    for (const auto& [symbol, value] : path.bindings) {
        append_canonical_field(out, symbol);
        append_canonical_field(out, value);
    }
    out << path.edges.size() << ":";
    for (int edge_id : path.edges) {
        append_canonical_field(out, canonical_edge_key(graph, edge_id));
    }
    return out.str();
}

static std::string canonical_terminal_state_key(const SemanticGraph& graph,
                                                const PathResult& path) {
    std::ostringstream out;
    append_canonical_field(out, canonical_node_key(graph, path.start_alpha));
    append_canonical_field(out, canonical_node_key(graph, path.final_node));
    append_canonical_field(out, path.reason);
    append_canonical_field(out, path.final_query);
    for (const auto& [symbol, value] : path.bindings) {
        append_canonical_field(out, symbol);
        append_canonical_field(out, value);
    }
    return out.str();
}

static std::string canonical_report_key(const BugReport& report) {
    std::ostringstream out;
    append_canonical_field(out, report.kind);
    append_canonical_field(out, report.zoneCut.value_or(""));
    append_canonical_field(out, report.nameserver.value_or(""));
    append_canonical_field(out, report.startName.value_or(""));
    append_canonical_field(out, report.query.value_or(""));
    append_canonical_field(out, report.rewrittenName.value_or(""));
    append_canonical_field(out, report.server.value_or(""));
    append_canonical_field(out, report.zone.value_or(""));
    append_canonical_field(out, report.reason);
    return out.str();
}

static GraphStateDigest compute_graph_state_digest(
    const SemanticGraph& graph,
    const std::vector<PathResult>& paths,
    const std::vector<BugReport>& reports) {
    GraphStateDigest result;
    std::vector<std::string> active_edges;
    std::vector<std::string> reachable_edges;
    active_edges.reserve(graph.edges.size());
    reachable_edges.reserve(graph.edges.size());
    for (const Edge& edge : graph.edges) {
        if (edge.deleted) continue;
        ++result.active_edges;
        std::string key = canonical_edge_key(graph, edge.id);
        active_edges.push_back(key);
        if (edge.reach == 1) {
            ++result.reachable_edges;
            reachable_edges.push_back(std::move(key));
        }
    }

    std::vector<std::string> path_keys;
    std::vector<std::string> state_keys;
    path_keys.reserve(paths.size());
    state_keys.reserve(paths.size());
    for (const PathResult& path : paths) {
        path_keys.push_back(canonical_path_key(graph, path));
        state_keys.push_back(canonical_terminal_state_key(graph, path));
    }

    std::vector<std::string> report_keys;
    report_keys.reserve(reports.size());
    for (const BugReport& report : reports) {
        report_keys.push_back(canonical_report_key(report));
    }

    result.active_edge_set =
        canonical_set_digest(std::move(active_edges));
    result.edge_set =
        canonical_set_digest(std::move(reachable_edges));
    result.path_set = canonical_set_digest(std::move(path_keys));
    result.terminal_state_set = canonical_set_digest(std::move(state_keys));
    result.report_set = canonical_set_digest(std::move(report_keys));
    return result;
}

static void print_graph_state_digest(const std::string& phase,
                                     const GraphStateDigest& digest,
                                     std::ostream& out) {
    out << "GraphStateDigest: phase=" << phase
        << " active_edges=" << digest.active_edges
        << " reachable_edges=" << digest.reachable_edges
        << " active_edge_set=" << digest.active_edge_set.digest
        << " edge_set=" << digest.edge_set.digest
        << " paths=" << digest.path_set.count
        << " path_set=" << digest.path_set.digest
        << " terminal_states=" << digest.terminal_state_set.count
        << " state_set=" << digest.terminal_state_set.digest
        << " reports=" << digest.report_set.count
        << " report_set=" << digest.report_set.digest
        << "\n";
}

static void print_graph_state_items(const std::string& phase,
                                    const SemanticGraph& graph,
                                    const std::vector<PathResult>& paths,
                                    std::ostream& out) {
    std::vector<std::string> active_edges;
    std::vector<std::string> reachable_edges;
    active_edges.reserve(graph.edges.size());
    reachable_edges.reserve(graph.edges.size());
    for (const Edge& edge : graph.edges) {
        if (edge.deleted) continue;
        std::string key = canonical_edge_key(graph, edge.id);
        active_edges.push_back(key);
        if (edge.reach == 1) reachable_edges.push_back(std::move(key));
    }
    std::sort(active_edges.begin(), active_edges.end());
    active_edges.erase(
        std::unique(active_edges.begin(), active_edges.end()),
        active_edges.end());
    std::sort(reachable_edges.begin(), reachable_edges.end());
    reachable_edges.erase(
        std::unique(reachable_edges.begin(), reachable_edges.end()),
        reachable_edges.end());
    for (const std::string& edge : active_edges) {
        out << "GraphStateActiveEdge: phase=" << phase << " key=" << edge
            << "\n";
    }
    for (const std::string& edge : reachable_edges) {
        out << "GraphStateEdge: phase=" << phase << " key=" << edge << "\n";
    }

    std::vector<std::string> path_keys;
    std::vector<std::string> state_keys;
    path_keys.reserve(paths.size());
    state_keys.reserve(paths.size());
    for (const PathResult& path : paths) {
        path_keys.push_back(canonical_path_key(graph, path));
        state_keys.push_back(canonical_terminal_state_key(graph, path));
    }
    std::sort(path_keys.begin(), path_keys.end());
    path_keys.erase(std::unique(path_keys.begin(), path_keys.end()),
                    path_keys.end());
    std::sort(state_keys.begin(), state_keys.end());
    state_keys.erase(std::unique(state_keys.begin(), state_keys.end()),
                     state_keys.end());
    for (const std::string& path : path_keys) {
        out << "GraphStatePath: phase=" << phase << " key=" << path << "\n";
    }
    for (const std::string& state : state_keys) {
        out << "GraphStateTerminal: phase=" << phase << " key=" << state
            << "\n";
    }
}

static void print_bug_reports(const SemanticGraph& graph,
                              const std::vector<BugReport>& reports,
                              std::ostream& out) {
    out << "\n=== Bug Reports ===\n";
    if (reports.empty()) {
        out << "<none>\n";
        return;
    }

    for (const BugReport& r : reports) {
        out << "[" << r.kind << "]";
        if (r.zoneCut.has_value()) out << " zoneCut=" << *r.zoneCut;
        if (r.nameserver.has_value()) out << " nameserver=" << *r.nameserver;
        if (r.startName.has_value()) out << " start=" << *r.startName;
        if (r.query.has_value()) out << " query=" << *r.query;
        if (r.rewrittenName.has_value()) out << " target=" << *r.rewrittenName;
        if (r.server.has_value()) out << " server=" << *r.server;
        if (r.zone.has_value()) out << " zone=" << *r.zone;
        out << "\n";
        out << "reason=" << r.reason << "\n";
        out << "path=";
        if (r.path.empty()) {
            out << "<none>";
        } else {
            bool first = true;
            for (int eid : r.path) {
                if (eid < 0 || eid >= static_cast<int>(graph.edges.size())) continue;
                const Edge& e = graph.edges[eid];
                const Node& s = graph.nodes[e.src];
                const Node& d = graph.nodes[e.dst];
                if (!first) out << " | ";
                first = false;
                out << "[" << graph.servers[s.server].name
                    << " " << graph.zones[s.zone].origin << "] "
                    << s.name << " --" << edge_type_name(e.type)
                    << "/reach=" << e.reach << "--> " << d.name;
                if (s.server != d.server || s.zone != d.zone) {
                    out << " [dst " << graph.servers[d.server].name
                        << " " << graph.zones[d.zone].origin << "]";
                }
            }
        }
        out << "\n\n";
    }
}

static void print_edge_list(const SemanticGraph& graph,
                            const std::string& label,
                            const std::vector<int>& edges,
                            std::ostream& out) {
    out << label << "=";
    if (edges.empty()) {
        out << "<none>\n";
        return;
    }
    bool first = true;
    for (int eid : edges) {
        if (eid < 0 || eid >= static_cast<int>(graph.edges.size())) continue;
        const Edge& e = graph.edges[eid];
        const Node& s = graph.nodes[e.src];
        const Node& d = graph.nodes[e.dst];
        if (!first) out << " | ";
        first = false;
        out << "[" << eid << "] "
            << s.name << " --" << edge_type_name(e.type)
            << "/reach=" << e.reach;
        if (e.deleted) out << "/deleted";
        out << "--> " << d.name;
    }
    out << "\n";
}

static void print_node_list(const SemanticGraph& graph,
                            const std::string& label,
                            const std::vector<int>& nodes,
                            std::ostream& out) {
    out << label << "=";
    if (nodes.empty()) {
        out << "<none>\n";
        return;
    }
    bool first = true;
    for (int nid : nodes) {
        if (nid < 0 || nid >= static_cast<int>(graph.nodes.size())) continue;
        if (!first) out << " | ";
        first = false;
        out << "[" << nid << "] " << graph.nodes[nid].name;
    }
    out << "\n";
}

void print_incremental_result(const SemanticGraph& graph,
                              const IncrementalResult& result,
                              std::ostream& out,
                              double preparation_seconds = 0.0) {
    out << "\n=== Incremental Validation ===\n";
    print_edge_list(graph, "changed_edges", result.changed_edges, out);
    print_edge_list(graph, "reach_1_to_0", result.reach_1_to_0, out);
    print_edge_list(graph, "reach_0_to_1", result.reach_0_to_1, out);
    print_edge_list(graph, "added_edges", result.added_edges, out);
    print_edge_list(graph, "removed_edges", result.removed_edges, out);
    print_node_list(graph, "traversal_starts", result.traversal_starts, out);
    out << "affected_paths=" << result.affected_paths.size() << "\n";
    out << std::setprecision(12);
    out << "IncrementalTiming: prepare=" << preparation_seconds
        << " graph_update=" << result.graph_update_seconds
        << " local_traversal=" << result.local_traversal_seconds
        << " report_refresh=" << result.report_refresh_seconds
        << " total=" << (preparation_seconds + result.total_seconds) << "\n";
    if (!result.warnings.empty()) {
        out << "warnings=";
        bool first = true;
        for (const std::string& warning : result.warnings) {
            if (!first) out << " | ";
            first = false;
            out << warning;
        }
        out << "\n";
    }
    out << "new_reports:";
    print_bug_reports(graph, result.new_reports, out);
    out << "fixed_reports:";
    print_bug_reports(graph, result.fixed_reports, out);
    out << "all_reports_after:";
    print_bug_reports(graph, result.all_reports_after, out);
}

static void print_record(const RecordInput& r, std::ostream& out) {
    out << r.owner << " "
        << edge_type_name(r.type) << " "
        << r.rdata;
}

static void print_repair_action(const RepairAction& action, std::ostream& out) {
    out << "  " << (action.op == RepairOp::ADD ? "ADD" :
                    action.op == RepairOp::DELETE ? "DELETE" : "MODIFY") << " ";
    if (action.op == RepairOp::MODIFY) {
        if (action.old_record.has_value()) {
            print_record(*action.old_record, out);
        } else {
            out << "<missing-old-record>";
        }
        out << " -> ";
        if (action.new_record.has_value()) {
            print_record(*action.new_record, out);
        } else {
            out << "<missing-new-record>";
        }
    } else if (action.op == RepairOp::ADD && action.new_record.has_value()) {
        print_record(*action.new_record, out);
    } else if (action.op == RepairOp::DELETE && action.old_record.has_value()) {
        print_record(*action.old_record, out);
    } else {
        out << "<invalid-action>";
    }
    out << "\n";
    out << "target = " << action.target_server << " / " << action.target_zone << "\n";
    if (!action.rationale.empty()) {
        out << "action_reason = " << action.rationale << "\n";
    }
    out << "action_tsv = "
        << (action.op == RepairOp::ADD ? "ADD" :
            action.op == RepairOp::DELETE ? "DELETE" : "MODIFY");
    auto print_tsv_record = [&](const std::optional<RecordInput>& record) {
        if (!record.has_value()) {
            out << "\t<missing>\t<missing>\t<missing>\tOTHER\t<missing>";
            return;
        }
        out << "\t" << record->server
            << "\t" << record->zone
            << "\t" << record->owner
            << "\t" << edge_type_name(record->type)
            << "\t" << record->rdata;
    };
    if (action.op == RepairOp::ADD) {
        print_tsv_record(action.new_record);
    } else if (action.op == RepairOp::DELETE) {
        print_tsv_record(action.old_record);
    } else {
        print_tsv_record(action.old_record);
        print_tsv_record(action.new_record);
    }
    out << "\n";
}

static std::string repair_bug_label(const BugReport& bug) {
    std::ostringstream out;
    out << bug.kind << "(";
    if (bug.zoneCut.has_value()) {
        out << *bug.zoneCut;
        if (bug.nameserver.has_value()) out << ", " << *bug.nameserver;
    } else if (bug.startName.has_value()) {
        out << *bug.startName;
    } else if (bug.query.has_value()) {
        out << *bug.query;
    }
    out << ")";
    return out.str();
}

struct RepairBugGroup {
    std::string key;
    BugReport representative;
    size_t count = 0;
};

static int forward_base_edge_for_grouping(const SemanticGraph& graph, int edge_id) {
    std::set<int> seen;
    int current = edge_id;
    while (current >= 0 && current < static_cast<int>(graph.edges.size())) {
        if (!seen.insert(current).second) break;
        const Edge& e = graph.edges[current];
        if (is_base_type(e.type)) return current;
        auto it = graph.semantic_edge_origin.find(current);
        if (it == graph.semantic_edge_origin.end()) break;
        current = it->second;
    }
    return -1;
}

static std::string edge_record_group_key(const SemanticGraph& graph, int edge_id) {
    if (edge_id < 0 || edge_id >= static_cast<int>(graph.edges.size())) return "";
    const Edge& e = graph.edges[edge_id];
    if (e.src < 0 || e.src >= static_cast<int>(graph.nodes.size())) return "";
    const Node& src = graph.nodes[e.src];
    std::ostringstream out;
    out << graph.servers[src.server].name << "|"
        << graph.zones[src.zone].origin << "|"
        << src.name << "|"
        << edge_type_name(e.type) << "|"
        << e.record;
    return out.str();
}

static std::string rewrite_origin_set_key(const SemanticGraph& graph,
                                          const std::vector<int>& path) {
    std::set<std::string> records;
    for (int eid : path) {
        if (eid < 0 || eid >= static_cast<int>(graph.edges.size())) continue;
        const Edge& e = graph.edges[eid];
        if (e.type != EdgeType::CNAME &&
            e.type != EdgeType::DNAME &&
            e.type != EdgeType::CRew &&
            e.type != EdgeType::DRew) {
            continue;
        }
        int base = forward_base_edge_for_grouping(graph, eid);
        if (base < 0 || base >= static_cast<int>(graph.edges.size())) continue;
        if (graph.edges[base].type != EdgeType::CNAME &&
            graph.edges[base].type != EdgeType::DNAME) {
            continue;
        }
        records.insert(edge_record_group_key(graph, base));
    }

    std::ostringstream out;
    bool first = true;
    for (const std::string& rec : records) {
        if (!first) out << ";";
        first = false;
        out << rec;
    }
    return out.str();
}

static std::string repair_group_key(const SemanticGraph& graph, const BugReport& bug) {
    std::ostringstream key;
    key << bug.kind << "|";

    if (bug.kind == "MG" || bug.kind == "LD") {
        key << bug.zoneCut.value_or("") << "|"
            << bug.nameserver.value_or("") << "|"
            << bug.reason;
    } else if (bug.kind == "DI") {
        key << bug.zoneCut.value_or("") << "|"
            << bug.nameserver.value_or("") << "|"
            << bug.zone.value_or("") << "|"
            << bug.reason;
    } else if (bug.kind == "CZD") {
        key << bug.zoneCut.value_or("") << "|"
            << bug.zone.value_or("") << "|"
            << bug.reason;
    } else if (bug.kind == "RB") {
        key << bug.rewrittenName.value_or("") << "|"
            << bug.server.value_or("") << "|"
            << bug.zone.value_or("") << "|"
            << bug.reason;
    } else if (bug.kind == "RL" || bug.kind == "ML") {
        const std::string rewrite_key = rewrite_origin_set_key(graph, bug.path);
        if (!rewrite_key.empty()) {
            key << rewrite_key << "|" << bug.reason;
        } else {
            key << bug.startName.value_or("") << "|"
                << bug.query.value_or("") << "|"
                << bug.rewrittenName.value_or("") << "|"
                << bug.reason;
        }
    } else if (bug.kind == "STALE") {
        key << stale_repair_root_component(graph, bug);
    } else {
        key << bug.zoneCut.value_or("") << "|"
            << bug.nameserver.value_or("") << "|"
            << bug.startName.value_or("") << "|"
            << bug.query.value_or("") << "|"
            << bug.rewrittenName.value_or("") << "|"
            << bug.server.value_or("") << "|"
            << bug.zone.value_or("") << "|"
            << bug.reason;
    }

    return key.str();
}

static std::vector<RepairBugGroup> group_bug_reports_for_repair(
        const SemanticGraph& graph,
        const std::vector<BugReport>& reports,
        const std::optional<std::string>& kind_filter) {
    std::map<std::string, RepairBugGroup> grouped;
    for (const BugReport& report : reports) {
        if (kind_filter.has_value() && report.kind != *kind_filter) continue;
        const std::string key = repair_group_key(graph, report);
        RepairBugGroup& group = grouped[key];
        if (group.count == 0) {
            group.key = key;
            group.representative = report;
        } else {
            // Prefer a shorter witness path as the representative.  It usually
            // contains the same root-cause record with less irrelevant context.
            if (!report.path.empty() &&
                (group.representative.path.empty() ||
                 report.path.size() < group.representative.path.size())) {
                group.representative = report;
            }
        }
        ++group.count;
    }

    std::vector<RepairBugGroup> out;
    out.reserve(grouped.size());
    for (auto& [_, group] : grouped) {
        out.push_back(std::move(group));
    }
    return out;
}

static void print_repair_groups(const std::vector<RepairBugGroup>& groups,
                                std::ostream& out) {
    out << "\n=== Repair Groups ===\n";
    if (groups.empty()) {
        out << "<none>\n";
        return;
    }
    for (const RepairBugGroup& group : groups) {
        out << "[RepairGroup]\n";
        out << "group_key = " << group.key << "\n";
        out << "kind = " << group.representative.kind << "\n";
        out << "grouped_reports = " << group.count << "\n";
        out << "representative = "
            << repair_bug_label(group.representative) << "\n\n";
    }
}

static void print_repair_candidates(const std::vector<RepairCandidate>& candidates,
                                    std::ostream& out) {
    out << "\n=== Repair Candidates ===\n";
    if (candidates.empty()) {
        out << "<none>\n";
        return;
    }

    for (const RepairCandidate& c : candidates) {
        out << "[RepairCandidate]\n";
        out << "bug = " << repair_bug_label(c.bug) << "\n";
        out << "priority = " << c.priority << "\n";
        out << "risk = " << c.risk << "\n";
        out << "valid = " << (c.valid ? "true" : "false") << "\n";
        out << "grouped_reports = " << c.grouped_reports << "\n";
        out << "group_key = " << c.repair_group_key << "\n";
        out << "actions:\n";
        for (const RepairAction& action : c.actions) {
            print_repair_action(action, out);
        }
        out << "rationale = \"" << c.rationale << "\"\n";
        out << "expected_effect = \"" << c.expected_effect << "\"\n";
        out << "affected_paths = " << c.validation.affected_paths.size() << "\n";
        out << "new_reports = " << c.validation.new_reports.size() << "\n";
        out << "fixed_reports = " << c.validation.fixed_reports.size() << "\n\n";
    }
}

static std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    size_t begin = 0;
    while (true) {
        const size_t tab = line.find('\t', begin);
        if (tab == std::string::npos) {
            fields.push_back(line.substr(begin));
            break;
        }
        fields.push_back(line.substr(begin, tab - begin));
        begin = tab + 1;
    }
    return fields;
}

static RecordInput record_from_action_fields(const std::vector<std::string>& fields,
                                             size_t offset,
                                             size_t line_number) {
    if (offset + 5 > fields.size()) {
        throw std::runtime_error(
            "invalid action file line " + std::to_string(line_number) +
            ": incomplete DNS record");
    }
    RecordInput record{
        fields[offset],
        fields[offset + 1],
        fields[offset + 2],
        parse_edge_type(fields[offset + 3]),
        fields[offset + 4]
    };
    if (!is_base_type(record.type)) {
        throw std::runtime_error(
            "invalid action file line " + std::to_string(line_number) +
            ": unsupported RR type " + fields[offset + 3]);
    }
    return record;
}

static std::vector<RepairAction> load_repair_actions(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("cannot open incremental action file: " + path);
    }

    std::vector<RepairAction> actions;
    std::string line;
    size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.front() == '#') continue;
        const std::vector<std::string> fields = split_tabs(line);
        if (fields.empty()) continue;

        RepairAction action;
        if (fields[0] == "ADD" || fields[0] == "DELETE") {
            if (fields.size() != 6) {
                throw std::runtime_error(
                    "invalid action file line " + std::to_string(line_number) +
                    ": ADD/DELETE requires 6 tab-separated fields");
            }
            RecordInput record = record_from_action_fields(fields, 1, line_number);
            action.target_server = record.server;
            action.target_zone = record.zone;
            if (fields[0] == "ADD") {
                action.op = RepairOp::ADD;
                action.new_record = std::move(record);
            } else {
                action.op = RepairOp::DELETE;
                action.old_record = std::move(record);
            }
        } else if (fields[0] == "MODIFY") {
            if (fields.size() != 11) {
                throw std::runtime_error(
                    "invalid action file line " + std::to_string(line_number) +
                    ": MODIFY requires 11 tab-separated fields");
            }
            action.op = RepairOp::MODIFY;
            action.old_record = record_from_action_fields(fields, 1, line_number);
            action.new_record = record_from_action_fields(fields, 6, line_number);
            action.target_server = action.new_record->server;
            action.target_zone = action.new_record->zone;
        } else {
            throw std::runtime_error(
                "invalid action file line " + std::to_string(line_number) +
                ": expected ADD, DELETE, or MODIFY");
        }
        actions.push_back(std::move(action));
    }

    if (actions.empty()) {
        throw std::runtime_error("incremental action file contains no actions: " + path);
    }
    return actions;
}

static GraphBuilder build_example() {
    GraphBuilder b;

    // Parent com. zone hosted at the gTLD server.
    b.addRecord("a.gtld-server.net.", "com.", "bank.com.", EdgeType::NS, "ns1.bank.com.");
    b.addRecord("a.gtld-server.net.", "com.", "coinsbank.com.", EdgeType::NS, "ns1.coinsbank.com.");
    b.addRecord("a.gtld-server.net.", "com.", "ns1.bank.com.", EdgeType::A, "16.17.16.17");
    b.addRecord("a.gtld-server.net.", "com.", "ns1.coinsbank.com.", EdgeType::A, "16.17.16.18");

    // ns1.bank.com. hosts bank.com.; it includes DNAME, CNAME, wildcard, and terminals.
    b.addRecord("ns1.bank.com.", "bank.com.", "bank.com.", EdgeType::NS, "ns1.bank.com.");
    b.addRecord("ns1.bank.com.", "bank.com.", "ns1.bank.com.", EdgeType::A, "10.0.0.1");
    b.addRecord("ns1.bank.com.", "bank.com.", "money.bank.com.", EdgeType::DNAME, "coinsbank.com.");
    b.addRecord("ns1.bank.com.", "bank.com.", "www.bank.com.", EdgeType::CNAME, "m.coinsbank.com.");
    b.addRecord("ns1.bank.com.", "bank.com.", "*.bank.com.", EdgeType::A, "10.0.0.9");
    b.addRecord("ns1.bank.com.", "bank.com.", "mail.bank.com.", EdgeType::MX, "mx.bank.com.");
    b.addRecord("ns1.bank.com.", "bank.com.", "txt.bank.com.", EdgeType::TXT, "\"bank txt\"");

    // The same physical server also hosts coinsbank.com.; this exercises same-server rewrite.
    b.addRecord("ns1.bank.com.", "coinsbank.com.", "coinsbank.com.", EdgeType::NS, "ns1.bank.com.");
    b.addRecord("ns1.bank.com.", "coinsbank.com.", "m.coinsbank.com.", EdgeType::A, "10.0.1.1");
    b.addRecord("ns1.bank.com.", "coinsbank.com.", "*.coinsbank.com.", EdgeType::TXT, "\"wild coinsbank\"");
    b.addRecord("ns1.bank.com.", "coinsbank.com.", "alias.coinsbank.com.", EdgeType::CNAME, "m.coinsbank.com.");

    // A second server hosts coinsbank.com.; this exercises cross-server CRew/DRew reach rules.
    b.addRecord("ns1.coinsbank.com.", "coinsbank.com.", "coinsbank.com.", EdgeType::NS, "ns1.coinsbank.com.");
    b.addRecord("ns1.coinsbank.com.", "coinsbank.com.", "ns1.coinsbank.com.", EdgeType::A, "10.0.2.1");
    b.addRecord("ns1.coinsbank.com.", "coinsbank.com.", "m.coinsbank.com.", EdgeType::A, "10.0.2.2");
    b.addRecord("ns1.coinsbank.com.", "coinsbank.com.", "*.coinsbank.com.", EdgeType::A, "10.0.2.9");

    return b;
}

} // namespace semantic_dns

int main(int argc, char** argv) {
    using namespace semantic_dns;

    try {
        std::optional<std::string> facts_path;
        std::optional<std::string> output_path;
        enum class IncMode { None, Add, Delete, Modify, Sequence };
        IncMode inc_mode = IncMode::None;
        std::optional<RecordInput> inc_record;
        std::optional<RecordInput> inc_new_record;
        std::optional<std::string> inc_actions_path;
        bool generate_repairs = false;
        bool repair_groups_only = false;
        bool use_example = false;
        std::optional<std::string> repair_kind_filter;
        size_t repair_limit = 0;
        int thread_count = 0;
        bool verbose_output = false;
        bool summary_only = false;
        bool reports_only = false;
        bool timing_output = false;
        bool validate_invariants = false;
        bool equivalence_digest = false;
        bool equivalence_dump = false;
        bool server_views_complete = true;

        auto parse_record_args = [&](int& i) -> RecordInput {
            if (i + 5 >= argc) {
                throw std::runtime_error("incremental operation needs: server zone owner type rdata");
            }
            RecordInput r;
            r.server = argv[++i];
            r.zone = argv[++i];
            r.owner = argv[++i];
            r.type = parse_edge_type(argv[++i]);
            r.rdata = argv[++i];
            if (!is_base_type(r.type)) {
                throw std::runtime_error("incremental operation only supports base RR types");
            }
            return r;
        };

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-o" || arg == "--output") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("missing output path after " + arg);
                }
                output_path = argv[++i];
            } else if (arg == "--inc-add") {
                if (inc_mode != IncMode::None) {
                    throw std::runtime_error("only one incremental operation is supported per run");
                }
                inc_mode = IncMode::Add;
                inc_record = parse_record_args(i);
            } else if (arg == "--inc-delete") {
                if (inc_mode != IncMode::None) {
                    throw std::runtime_error("only one incremental operation is supported per run");
                }
                inc_mode = IncMode::Delete;
                inc_record = parse_record_args(i);
            } else if (arg == "--inc-modify") {
                if (inc_mode != IncMode::None) {
                    throw std::runtime_error("only one incremental operation is supported per run");
                }
                inc_mode = IncMode::Modify;
                inc_record = parse_record_args(i);
                inc_new_record = parse_record_args(i);
            } else if (arg == "--inc-actions") {
                if (inc_mode != IncMode::None) {
                    throw std::runtime_error("only one incremental operation is supported per run");
                }
                if (i + 1 >= argc) {
                    throw std::runtime_error("missing TSV path after --inc-actions");
                }
                inc_mode = IncMode::Sequence;
                inc_actions_path = argv[++i];
            } else if (arg == "--repairs") {
                generate_repairs = true;
            } else if (arg == "--repair-groups-only") {
                repair_groups_only = true;
            } else if (arg == "--repairs-kind") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("missing kind after --repairs-kind");
                }
                generate_repairs = true;
                repair_kind_filter = argv[++i];
            } else if (arg == "--repairs-limit") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("missing number after --repairs-limit");
                }
                generate_repairs = true;
                repair_limit = static_cast<size_t>(std::stoul(argv[++i]));
            } else if (arg == "--threads") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("missing number after --threads");
                }
                thread_count = std::stoi(argv[++i]);
            } else if (arg == "--example") {
                use_example = true;
            } else if (arg == "--verbose") {
                verbose_output = true;
            } else if (arg == "--summary-only" || arg == "--compact") {
                summary_only = true;
            } else if (arg == "--reports-only") {
                reports_only = true;
            } else if (arg == "--timing") {
                timing_output = true;
            } else if (arg == "--validate-invariants") {
                validate_invariants = true;
            } else if (arg == "--equivalence-digest") {
                equivalence_digest = true;
            } else if (arg == "--equivalence-dump") {
                equivalence_digest = true;
                equivalence_dump = true;
            } else if (arg == "--server-views") {
                if (i + 1 >= argc) {
                    throw std::runtime_error(
                        "missing mode after --server-views (complete|sampled)");
                }
                const std::string mode = argv[++i];
                if (mode == "complete") {
                    server_views_complete = true;
                } else if (mode == "sampled") {
                    server_views_complete = false;
                } else {
                    throw std::runtime_error(
                        "invalid --server-views mode: " + mode +
                        " (expected complete or sampled)");
                }
            } else if (!facts_path.has_value()) {
                facts_path = arg;
            } else if (!output_path.has_value()) {
                output_path = arg;
            } else {
                throw std::runtime_error("too many arguments");
            }
        }
        // Benchmark runs use --summary-only and need stable machine-readable
        // timing columns.  Enable timing implicitly in compact mode so an older
        // driver that forgets --timing cannot silently produce empty timing
        // fields.
        if (summary_only) {
            timing_output = true;
        }

        using Clock = std::chrono::steady_clock;
        auto seconds = [](Clock::time_point a, Clock::time_point b) {
            return std::chrono::duration<double>(b - a).count();
        };

        auto total_start = Clock::now();
        double load_facts_seconds = 0.0;
        double compute_reach_seconds = 0.0;
        double traverse_dfs_seconds = 0.0;
        double traverse_core_seconds = 0.0;
        double detect_inline_seconds = 0.0;
        double detect_bugs_seconds = 0.0;
        BugDetector::Timing detect_timing;
        GraphBuilder::BuildTiming build_timing;
        GraphBuilder::SemanticBuildStats semantic_stats;

        GraphBuilder builder;
        if (facts_path.has_value()) {
            auto t0 = Clock::now();
            builder.loadFacts(*facts_path);
            auto t1 = Clock::now();
            load_facts_seconds = seconds(t0, t1);
        } else if (use_example) {
            builder = build_example();
        } else {
            throw std::runtime_error("missing ZoneRecord.facts input; use --example to run the built-in sample");
        }

        SemanticGraph graph = builder.build(&build_timing,
                                            validate_invariants,
                                            &semantic_stats);
        ReachComputer reach(graph);
        auto reach_start = Clock::now();
        reach.ComputeReach();
        auto reach_end = Clock::now();
        compute_reach_seconds = seconds(reach_start, reach_end);

        std::ofstream file_out;
        std::ostream* out = &std::cout;
        if (output_path.has_value()) {
            file_out.open(*output_path, std::ios::out | std::ios::trunc);
            if (!file_out.is_open()) {
                throw std::runtime_error("cannot open output file: " + *output_path);
            }
            out = &file_out;
        }

        bool compact_output = generate_repairs || repair_groups_only ||
                              inc_mode != IncMode::None ||
                              summary_only || reports_only;

        if (!compact_output || verbose_output) {
            print_edges(graph, *out);
        }

        BugDetector detector(graph, server_views_complete);
        detector.beginPathDetection();
        const bool store_paths =
            equivalence_digest || !compact_output || verbose_output;
        std::vector<int> start_nodes = collect_reachable_entry_nodes(graph);

        std::vector<PathResult> paths;
        if (store_paths) {
            paths.reserve(graph.edges.size());
        }
        size_t path_count = 0;
        auto dfs_start = Clock::now();
#ifdef _OPENMP
        int effective_threads = thread_count > 0 ? thread_count : omp_get_max_threads();
        if (effective_threads < 1) effective_threads = 1;
        if (effective_threads > 1 && start_nodes.size() > 1) {
            #pragma omp parallel num_threads(effective_threads)
            {
                PathTraverser local_traverser(graph);
                BugDetector local_detector(graph, server_views_complete);
                local_detector.beginPathDetection();
                std::vector<PathResult> local_paths_all;
                if (store_paths) local_paths_all.reserve(256);
                size_t local_path_count = 0;
                double local_detect_inline_seconds = 0.0;

                #pragma omp for schedule(dynamic, 16)
                for (int i = 0; i < static_cast<int>(start_nodes.size()); ++i) {
                    if (store_paths) {
                        std::vector<PathResult> local_paths =
                            local_traverser.traverseFromNode(
                                start_nodes[static_cast<size_t>(i)],
                                24,
                                [&](const PathResult& path) {
                                    const auto observe_start = Clock::now();
                                    local_detector.observePath(path);
                                    local_detect_inline_seconds +=
                                        seconds(observe_start, Clock::now());
                                });
                        local_path_count += local_paths.size();
                        local_paths_all.insert(local_paths_all.end(),
                                               std::make_move_iterator(local_paths.begin()),
                                               std::make_move_iterator(local_paths.end()));
                    } else {
                        local_path_count += local_traverser.traverseFromNodeStreaming(
                            start_nodes[static_cast<size_t>(i)],
                            24,
                            [&](const PathView& path) {
                                const auto observe_start = Clock::now();
                                local_detector.observePathView(path);
                                local_detect_inline_seconds +=
                                    seconds(observe_start, Clock::now());
                            });
                    }
                }

                #pragma omp critical
                {
                    path_count += local_path_count;
                    detect_inline_seconds += local_detect_inline_seconds;
                    detector.absorbObservedFrom(local_detector);
                    if (store_paths) {
                        paths.insert(paths.end(),
                                     std::make_move_iterator(local_paths_all.begin()),
                                     std::make_move_iterator(local_paths_all.end()));
                    }
                }
            }
        } else
#endif
        {
            PathTraverser traverser(graph);
            for (int start : start_nodes) {
                if (store_paths) {
                    std::vector<PathResult> local_paths = traverser.traverseFromNode(
                        start,
                        24,
                        [&](const PathResult& path) {
                            const auto observe_start = Clock::now();
                            detector.observePath(path);
                            detect_inline_seconds +=
                                seconds(observe_start, Clock::now());
                        });
                    path_count += local_paths.size();
                    paths.insert(paths.end(),
                                 std::make_move_iterator(local_paths.begin()),
                                 std::make_move_iterator(local_paths.end()));
                } else {
                    path_count += traverser.traverseFromNodeStreaming(
                        start,
                        24,
                        [&](const PathView& path) {
                            const auto observe_start = Clock::now();
                            detector.observePathView(path);
                            detect_inline_seconds +=
                                seconds(observe_start, Clock::now());
                        });
                }
            }
        }
        auto dfs_end = Clock::now();
        traverse_dfs_seconds = seconds(dfs_start, dfs_end);
        traverse_core_seconds =
            std::max(0.0, traverse_dfs_seconds - detect_inline_seconds);
        if (!compact_output || verbose_output) {
            print_paths(graph, paths, *out);
        }

        auto detect_start = Clock::now();
        std::vector<BugReport> reports = detector.finishPathDetection(&detect_timing);
        auto detect_end = Clock::now();
        detect_bugs_seconds = seconds(detect_start, detect_end);
        if (!compact_output || verbose_output || reports_only) {
            print_bug_reports(graph, reports, *out);
        }

        *out << "\nSummary: servers=" << graph.servers.size()
             << " zones=" << graph.zones.size()
             << " nodes=" << graph.nodes.size()
             << " edges=" << graph.edges.size()
             << " paths=" << path_count
             << " bugs=" << reports.size() << "\n";
        std::map<std::string, size_t> bug_kind_counts;
        for (const BugReport& report : reports) {
            ++bug_kind_counts[report.kind];
        }
        *out << "BugStats:";
        if (bug_kind_counts.empty()) {
            *out << " <none>";
        } else {
            for (const auto& [kind, count] : bug_kind_counts) {
                *out << " " << kind << "=" << count;
            }
        }
        *out << "\n";
        if (timing_output) {
            auto total_end = Clock::now();
            *out << std::setprecision(12);
            *out << "Timing: load_facts=" << load_facts_seconds
                 << " build_base=" << build_timing.base_seconds
                 << " build_semantic=" << build_timing.semantic_seconds
                 << " build_invariants=" << build_timing.invariant_seconds
                 << " compute_reach=" << compute_reach_seconds
                 << " traverse_dfs=" << traverse_dfs_seconds
                 << " traverse_core=" << traverse_core_seconds
                 << " detect_inline=" << detect_inline_seconds
                 << " detect_bugs=" << detect_bugs_seconds
                 << " detect_delegation=" << detect_timing.delegation_seconds
                 << " detect_czd=" << detect_timing.czd_seconds
                 << " detect_rewrite=" << detect_timing.rewrite_seconds
                 << " total=" << seconds(total_start, total_end) << "\n";
            *out << "SemanticBuildStats: owner_nodes=" << semantic_stats.owner_nodes
                 << " base_ns=" << semantic_stats.base_ns
                 << " base_cname=" << semantic_stats.base_cname
                 << " base_dname=" << semantic_stats.base_dname
                 << " del_candidates_checked=" << semantic_stats.del_candidates_checked
                 << " crew_candidates_checked=" << semantic_stats.crew_candidates_checked
                 << " drew_candidates_checked=" << semantic_stats.drew_candidates_checked
                 << " del_edges_added=" << semantic_stats.del_edges_added
                 << " crew_edges_added=" << semantic_stats.crew_edges_added
                 << " drew_edges_added=" << semantic_stats.drew_edges_added
                 << "\n";
        }
        if (equivalence_digest) {
            print_graph_state_digest(
                "baseline",
                compute_graph_state_digest(graph, paths, reports),
                *out);
            if (equivalence_dump) {
                print_graph_state_items("baseline", graph, paths, *out);
            }
        }
        out->flush();

        if (inc_mode != IncMode::None) {
            std::vector<RepairAction> actions;
            if (inc_mode == IncMode::Sequence) {
                actions = load_repair_actions(*inc_actions_path);
            } else {
                RepairAction action;
                if (inc_mode == IncMode::Add) {
                    action.op = RepairOp::ADD;
                    action.new_record = *inc_record;
                    action.target_server = inc_record->server;
                    action.target_zone = inc_record->zone;
                } else if (inc_mode == IncMode::Delete) {
                    action.op = RepairOp::DELETE;
                    action.old_record = *inc_record;
                    action.target_server = inc_record->server;
                    action.target_zone = inc_record->zone;
                } else {
                    action.op = RepairOp::MODIFY;
                    action.old_record = *inc_record;
                    action.new_record = *inc_new_record;
                    action.target_server = inc_new_record->server;
                    action.target_zone = inc_new_record->zone;
                }
                actions.push_back(std::move(action));
            }
            const auto prepare_start = Clock::now();
            IncrementalValidator validator(graph, reports, server_views_complete);
            const double preparation_seconds =
                seconds(prepare_start, Clock::now());
            IncrementalResult inc_result =
                validator.ApplyChangeSequence(actions);
            print_incremental_result(graph, inc_result, *out, preparation_seconds);
            if (equivalence_digest) {
                PathTraverser audit_traverser(graph);
                std::vector<PathResult> audit_paths =
                    audit_traverser.traverseAll();
                print_graph_state_digest(
                    "post_update",
                    compute_graph_state_digest(
                        graph, audit_paths, inc_result.all_reports_after),
                    *out);
                if (equivalence_dump) {
                    print_graph_state_items(
                        "post_update", graph, audit_paths, *out);
                }
            }
        }

        if (generate_repairs || repair_groups_only) {
            std::vector<RepairBugGroup> repair_groups =
                group_bug_reports_for_repair(graph, reports, repair_kind_filter);
            print_repair_groups(repair_groups, *out);
            if (!generate_repairs) {
                if (output_path.has_value()) {
                    std::cout << "Output written to: " << *output_path << "\n";
                }
                return 0;
            }

            RepairCandidateGenerator generator(graph, reports);
            std::vector<RepairCandidate> all_candidates;
            size_t processed = 0;
            for (const RepairBugGroup& group : repair_groups) {
                if (repair_limit != 0 && processed >= repair_limit) {
                    break;
                }
                std::vector<RepairCandidate> candidates =
                    generator.generateAndValidate(group.representative);
                for (RepairCandidate& candidate : candidates) {
                    candidate.grouped_reports = group.count;
                    candidate.repair_group_key = group.key;
                }
                all_candidates.insert(all_candidates.end(),
                                      candidates.begin(), candidates.end());
                ++processed;
            }
            std::sort(all_candidates.begin(), all_candidates.end(),
                      [](const RepairCandidate& a, const RepairCandidate& b) {
                          if (a.priority != b.priority) return a.priority < b.priority;
                          if (a.risk != b.risk) return a.risk < b.risk;
                          if (a.grouped_reports != b.grouped_reports) {
                              return a.grouped_reports > b.grouped_reports;
                          }
                          return a.actions.size() < b.actions.size();
                      });
            print_repair_candidates(all_candidates, *out);
        }

        if (output_path.has_value()) {
            std::cout << "Output written to: " << *output_path << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "semantic_graph error: " << e.what() << "\n";
        std::cerr << "Usage: semantic_graph [ZoneRecord.facts] [-o output.txt]\n"
                  << "       semantic_graph --example [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --inc-add server zone owner type rdata [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --inc-delete server zone owner type rdata [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --inc-modify old_server old_zone old_owner old_type old_rdata new_server new_zone new_owner new_type new_rdata [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --inc-actions actions.tsv [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --summary-only [--timing] [--threads N] [--validate-invariants] [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --reports-only [--threads N] [--server-views complete|sampled] [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --equivalence-digest [--equivalence-dump] [incremental options] [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --repair-groups-only [--reports-only] [-o output.txt]\n"
                  << "       semantic_graph [ZoneRecord.facts] --repairs [--repairs-kind RB] [--repairs-limit N] [--verbose] [-o output.txt]\n";
        return 1;
    }

    return 0;
}
