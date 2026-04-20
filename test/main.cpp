#define __EMBEDDED_SOUFFLE__
#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <filesystem>
#include <algorithm>
#include <mutex>
#include <atomic>
#include <omp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <charconv>
#include <unordered_map>
#include <fstream>
#include <optional>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <nlohmann/json.hpp>

// 如果是 Windows，需要不同的 Mmap 实现；这里假设是 Linux/Unix 环境
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "verifier.cpp"

namespace fs = std::filesystem;

std::ofstream facts_out_file;
std::mutex facts_mutex;

// ==========================================
// 1. Mmap 封装
// ==========================================
class MappedFile {
    char* data_ = nullptr;
    size_t size_ = 0;
#ifdef _WIN32
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hMap_ = NULL;
#else
    int fd_ = -1;
#endif
public:
    explicit MappedFile(const fs::path& path) {
#ifdef _WIN32
        hFile_ = CreateFileA(path.string().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile_ == INVALID_HANDLE_VALUE) return;
        size_ = GetFileSize(hFile_, NULL);
        if (size_ == 0) return;
        hMap_ = CreateFileMappingA(hFile_, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMap_ == NULL) return;
        data_ = static_cast<char*>(MapViewOfFile(hMap_, FILE_MAP_READ, 0, 0, 0));
#else
        fd_ = open(path.c_str(), O_RDONLY);
        if (fd_ == -1) return;
        struct stat sb;
        if (fstat(fd_, &sb) == -1) return;
        size_ = static_cast<size_t>(sb.st_size);
        if (size_ == 0) return;
        data_ = static_cast<char*>(mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0));
        if (data_ == MAP_FAILED) {
            data_ = nullptr;
            size_ = 0;
        }
#endif
    }

    ~MappedFile() {
#ifdef _WIN32
        if (data_) UnmapViewOfFile(data_);
        if (hMap_) CloseHandle(hMap_);
        if (hFile_ != INVALID_HANDLE_VALUE) CloseHandle(hFile_);
#else
        if (data_) munmap(data_, size_);
        if (fd_ != -1) close(fd_);
#endif
    }

    const char* data() const { return data_; }
    size_t size() const { return size_; }
    bool is_valid() const { return data_ != nullptr && size_ > 0; }
};

// ==========================================
// 2. 辅助函数
// ==========================================
inline bool is_rr_type_fast(const char* s, size_t len) {
    if (len == 0 || len > 10) return false;

    char c0 = s[0] & 0xDF;

    if (c0 == 'A') {
        return (len == 1) || (len == 4 && (s[1] & 0xDF) == 'A' && (s[2] & 0xDF) == 'A' && (s[3] & 0xDF) == 'A');
    }
    if (c0 == 'N') {
        if (len == 2 && (s[1] & 0xDF) == 'S') return true;
        if (len == 4 && (s[1] & 0xDF) == 'S' && (s[2] & 0xDF) == 'E' && (s[3] & 0xDF) == 'C') return true;
        return false;
    }
    if (c0 == 'C') return (len == 5);                 // CNAME
    if (c0 == 'S') return (len == 3);                 // SOA, SRV
    if (c0 == 'M') return (len == 2);                 // MX
    if (c0 == 'T') return (len == 3);                 // TXT
    if (c0 == 'P') return (len == 3);                 // PTR
    if (c0 == 'D') return (len == 2 || len == 5 || len == 6); // DS, DNAME, DNSKEY
    if (c0 == 'R') return (len == 5);                 // RRSIG
    return false;
}

inline std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c |= 0x20;
    }
    return s;
}

inline void clean_domain_into(const char* src, size_t len, std::string& buffer) {
    buffer.clear();
    if (len == 0) return;

    buffer.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        char c = src[i];
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        buffer.push_back(c);
    }
}

inline std::string clean_domain_copy(const char* src, size_t len) {
    std::string out;
    clean_domain_into(src, len, out);
    return out;
}

inline std::string trim_copy(std::string_view sv) {
    size_t l = 0;
    size_t r = sv.size();
    while (l < r && std::isspace(static_cast<unsigned char>(sv[l]))) ++l;
    while (r > l && std::isspace(static_cast<unsigned char>(sv[r - 1]))) --r;
    return std::string(sv.substr(l, r - l));
}

inline bool is_blank_or_comment(const char* start, const char* end) {
    const char* p = start;
    while (p < end && std::isspace(static_cast<unsigned char>(*p))) ++p;
    return (p >= end || *p == ';');
}

inline std::string normalize_origin(std::string origin) {
    origin = to_lower_ascii(trim_copy(origin));
    if (!origin.empty() && origin.back() != '.') {
        origin.push_back('.');
    }
    return origin;
}

inline std::string origin_from_filename(const fs::path& path) {
    return normalize_origin(path.stem().string()); // 去掉 .txt
}

inline bool looks_like_rr_class(const char* s, size_t len) {
    if (len == 2) {
        char c0 = s[0] & 0xDF;
        char c1 = s[1] & 0xDF;
        return (c0 == 'I' && c1 == 'N') ||
               (c0 == 'C' && c1 == 'H') ||
               (c0 == 'H' && c1 == 'S');
    }
    return false;
}

inline bool looks_numeric(const char* s, size_t len) {
    if (len == 0) return false;
    for (size_t i = 0; i < len; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
    }
    return true;
}

// 把 owner/rdata 中的域名按当前 origin 展开
// 规则：
//   - "@" => 当前 origin
//   - 末尾有 '.' => 绝对域名，直接保留
//   - 其他 => 相对域名，拼接 ".origin"
inline std::string absolutize_name(const std::string& token, const std::string& current_origin) {
    if (token.empty()) return current_origin;
    if (token == "@") return current_origin;

    std::string t = to_lower_ascii(token);
    if (!t.empty() && t.back() == '.') {
        return t;
    }

    if (current_origin.empty()) {
        return t;
    }

    std::string out = t;
    if (!out.empty()) out.push_back('.');
    out += current_origin;
    return out;
}

inline bool rr_data_is_domain_name(const std::string& rrtype) {
    return rrtype == "CNAME" || rrtype == "DNAME" || rrtype == "NS" ||
           rrtype == "PTR"   || rrtype == "MX"    || rrtype == "SRV";
}

// 为 MX/SRV 提取域名型目标；其他类型直接按原始串保存
inline std::string normalize_rdata(const std::string& rrtype,
                                   const char* data_ptr,
                                   const char* real_end,
                                   const std::string& current_origin) {
    if (data_ptr >= real_end) return "";

    std::string raw(data_ptr, real_end - data_ptr);

    if (rrtype == "MX") {
        const char* p = data_ptr;
        while (p < real_end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        while (p < real_end && std::isspace(static_cast<unsigned char>(*p))) ++p;
        if (p < real_end) {
            return absolutize_name(trim_copy(std::string_view(p, real_end - p)), current_origin);
        }
        return trim_copy(raw);
    }

    if (rrtype == "SRV") {
        const char* p = data_ptr;
        int nums = 0;
        while (p < real_end && nums < 3) {
            while (p < real_end && std::isspace(static_cast<unsigned char>(*p))) ++p;
            const char* tok = p;
            while (p < real_end && !std::isspace(static_cast<unsigned char>(*p))) ++p;
            if (tok < p) ++nums;
        }
        while (p < real_end && std::isspace(static_cast<unsigned char>(*p))) ++p;
        if (p < real_end) {
            return absolutize_name(trim_copy(std::string_view(p, real_end - p)), current_origin);
        }
        return trim_copy(raw);
    }

    if (rr_data_is_domain_name(rrtype)) {
        return absolutize_name(trim_copy(raw), current_origin);
    }

    return trim_copy(raw);
}

// 尝试处理 $ORIGIN 指令
inline bool handle_origin_directive(const char* line_start,
                                    const char* line_end,
                                    std::string& current_origin) {
    const char* p = line_start;
    while (p < line_end && std::isspace(static_cast<unsigned char>(*p))) ++p;
    if (p >= line_end) return false;
    if (*p != '$') return false;

    const char* tok_start = p;
    while (p < line_end && !std::isspace(static_cast<unsigned char>(*p))) ++p;
    std::string directive = to_lower_ascii(std::string(tok_start, p - tok_start));
    if (directive != "$origin") return false;

    while (p < line_end && std::isspace(static_cast<unsigned char>(*p))) ++p;
    if (p >= line_end) return true; // 空 $ORIGIN，忽略但视为已处理
    const char* arg_start = p;
    while (p < line_end && *p != ';') ++p;
    std::string arg = trim_copy(std::string_view(arg_start, p - arg_start));
    if (!arg.empty()) {
        current_origin = absolutize_name(arg, current_origin);
    }
    return true;
}

// ==========================================
// 3. 核心处理逻辑
// ==========================================
void process_file(const fs::path& path,
                  const std::string& server_id,
                  const std::string& file_origin,
                  souffle::Relation* rel,
                  std::mutex& rel_mutex,
                  std::atomic<size_t>& global_counter,
                  size_t max_records) {
    MappedFile mfile(path);
    if (!mfile.is_valid()) return;

    const char* ptr = mfile.data();
    const char* end = ptr + mfile.size();

    std::string current_origin = file_origin;   // 当前生效 origin，可被 $ORIGIN 修改
    std::string fixed_zone = file_origin;       // ZoneRecord 的 zone 字段固定取文件对应区域
    std::string last_owner = file_origin;       // 处理空 owner 继承
    std::string name_buf;
    std::string data_buf;
    std::string temp_type_str;

    std::vector<souffle::tuple> batch_tuples;
    batch_tuples.reserve(500);

    while (ptr < end) {
        const char* line_start = ptr;
        while (ptr < end && *ptr != '\n') ++ptr;
        const char* line_end = ptr;
        if (line_end > line_start && *(line_end - 1) == '\r') --line_end;
        if (ptr < end) ++ptr;

        if (is_blank_or_comment(line_start, line_end)) continue;

        // 处理 $ORIGIN
        if (handle_origin_directive(line_start, line_end, current_origin)) {
            // 同时把 last_owner 更新为新的 origin，避免后续空 owner 错位
            last_owner = current_origin;
            continue;
        }

        // 简化 tokenization（不处理引号内空格与括号多行）
        const char* part_ptrs[16];
        size_t part_lens[16];
        int part_count = 0;

        const char* p = line_start;
        while (p < line_end && part_count < 16) {
            while (p < line_end && std::isspace(static_cast<unsigned char>(*p))) ++p;
            if (p >= line_end || *p == ';') break;

            const char* token_start = p;
            while (p < line_end && !std::isspace(static_cast<unsigned char>(*p)) && *p != ';') ++p;

            part_ptrs[part_count] = token_start;
            part_lens[part_count] = static_cast<size_t>(p - token_start);
            ++part_count;
        }

        if (part_count < 2) continue;

        // 找 RR type 位置。支持：
        // owner type ...
        // owner ttl type ...
        // owner class type ...
        // owner ttl class type ...
        // 以及空 owner 继承时：
        // ttl class type ...
        // class type ...
        // type ...
        int type_idx = -1;
        for (int i = 0; i < part_count && i < 5; ++i) {
            if (is_rr_type_fast(part_ptrs[i], part_lens[i])) {
                type_idx = i;
                break;
            }
        }
        if (type_idx == -1) continue;

        // 记录数限制
        size_t current_count = global_counter.load(std::memory_order_relaxed);
        if (max_records > 0 && current_count >= max_records) break;

        size_t new_count = global_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        if (max_records > 0 && new_count > max_records) {
            global_counter.fetch_sub(1, std::memory_order_relaxed);
            break;
        }

        // owner 解析
        // 若 type_idx == 0，表示本行没有显式 owner，沿用上一条 owner
        if (type_idx == 0) {
            name_buf = last_owner;
        } else {
            std::string raw_owner = clean_domain_copy(part_ptrs[0], part_lens[0]);
            name_buf = absolutize_name(raw_owner, current_origin);
            last_owner = name_buf;
        }

        // type
        temp_type_str.assign(part_ptrs[type_idx], part_lens[type_idx]);
        for (auto& c : temp_type_str) {
            if (c >= 'a' && c <= 'z') c -= 0x20;
        }

        // TTL 解析：在 type 之前找纯数字 token
        souffle::RamSigned ttl = 0;
        for (int i = 0; i < type_idx; ++i) {
            if (looks_numeric(part_ptrs[i], part_lens[i])) {
                std::from_chars(part_ptrs[i], part_ptrs[i] + part_lens[i], ttl);
                break;
            }
        }

        // RDATA 起点
        const char* data_ptr = part_ptrs[type_idx] + part_lens[type_idx];
        while (data_ptr < line_end && std::isspace(static_cast<unsigned char>(*data_ptr))) ++data_ptr;

        const char* real_end = line_end;
        while (real_end > data_ptr && std::isspace(static_cast<unsigned char>(*(real_end - 1)))) --real_end;

        data_buf = normalize_rdata(temp_type_str, data_ptr, real_end, current_origin);

        souffle::tuple t(rel);
        t << server_id << fixed_zone << name_buf << temp_type_str << ttl << data_buf;
        batch_tuples.push_back(t);

        {
            std::lock_guard<std::mutex> lock(facts_mutex);
            facts_out_file << server_id << "\t"
                           << fixed_zone << "\t"
                           << name_buf << "\t"
                           << temp_type_str << "\t"
                           << ttl << "\t"
                           << data_buf << "\n";
        }

        if (batch_tuples.size() >= 500) {
            std::lock_guard<std::mutex> lock(rel_mutex);
            for (const auto& tup : batch_tuples) rel->insert(tup);
            batch_tuples.clear();
        }
    }

    if (!batch_tuples.empty()) {
        std::lock_guard<std::mutex> lock(rel_mutex);
        for (const auto& tup : batch_tuples) rel->insert(tup);
    }
}

// ==========================================
// 主函数
// ==========================================
struct FileMeta {
    std::string name_server;
    std::optional<std::string> origin;   // optional: if absent, infer from filename
};

struct Task {
    fs::path path;
    std::string server_id;
    std::string origin;
};

int main(int argc, char** argv) {
    size_t max_records = 0;

    if (argc < 2) {
        std::cerr << "Usage: ./direct_verifier <dataset_directory> [max_records]\n";
        std::cerr << "Example: ./direct_verifier ./data 1000000\n";
        std::cerr << "         ./direct_verifier ./data\n";
        return 1;
    }

    std::string root_dir = argv[1];

    if (argc >= 3) {
        char* endptr = nullptr;
        long long val = std::strtoll(argv[2], &endptr, 10);
        if (endptr != argv[2] && val > 0) {
            max_records = static_cast<size_t>(val);
            std::cout << ">>> Will read at most " << max_records << " records\n";
        } else {
            std::cerr << "Warning: Invalid max_records value '" << argv[2]
                      << "', reading all records\n";
        }
    }

    facts_out_file.open("ZoneRecord.facts");
    if (!facts_out_file.is_open()) {
        std::cerr << "Error: Could not open output facts file.\n";
        return 1;
    }

    auto* prog = souffle::ProgramFactory::newInstance("verifier");
    if (!prog) {
        std::cerr << "Error: Could not instantiate Souffle program.\n";
        return 1;
    }

    auto* zone_rel = prog->getRelation("ZoneRecord");
    if (!zone_rel) {
        std::cerr << "Error: Relation 'ZoneRecord' not found.\n";
        delete prog;
        return 1;
    }

    std::cout << ">>> Scanning files...\n";

    std::vector<Task> tasks;
    tasks.reserve(10000);

    // 每个目录对应一个 metadata.json；其中每个文件名对应 FileMeta
    std::unordered_map<fs::path, std::unordered_map<std::string, FileMeta>> dir_to_file_meta;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(root_dir)) {
            if (!entry.is_regular_file()) continue;

            const auto& p = entry.path();
            if (p.extension() != ".txt") continue;

            fs::path parent = p.parent_path();

            // 懒加载当前目录的 metadata.json
            if (dir_to_file_meta.find(parent) == dir_to_file_meta.end()) {
                fs::path meta_path = parent / "metadata.json";
                if (!fs::exists(meta_path)) {
                    std::cerr << "Warning: No metadata.json in " << parent << "\n";
                    // 标记为空，避免后续重复尝试加载
                    dir_to_file_meta[parent] = {};
                    continue;
                }

                std::ifstream meta_file(meta_path);
                if (!meta_file.is_open()) {
                    std::cerr << "Error: Could not open " << meta_path << "\n";
                    dir_to_file_meta[parent] = {};
                    continue;
                }

                nlohmann::json j;
                try {
                    meta_file >> j;
                } catch (const std::exception& e) {
                    std::cerr << "Error: Failed to parse " << meta_path
                              << ": " << e.what() << "\n";
                    dir_to_file_meta[parent] = {};
                    continue;
                }

                std::unordered_map<std::string, FileMeta> file_meta_map;

                if (j.contains("ZoneFiles") && j["ZoneFiles"].is_array()) {
                    for (const auto& zf : j["ZoneFiles"]) {
                        if (!zf.contains("FileName") || !zf.contains("NameServer")) {
                            continue;
                        }

                        std::string fname = zf["FileName"].get<std::string>();

                        FileMeta meta;
                        meta.name_server = zf["NameServer"].get<std::string>();

                        if (zf.contains("Origin") && !zf["Origin"].is_null()) {
                            meta.origin = normalize_origin(zf["Origin"].get<std::string>());
                        }

                        file_meta_map[fname] = std::move(meta);
                    }
                }

                dir_to_file_meta[parent] = std::move(file_meta_map);
            }

            auto& file_meta_map = dir_to_file_meta[parent];
            std::string fname = p.filename().string();

            auto it = file_meta_map.find(fname);
            if (it != file_meta_map.end()) {
                const FileMeta& meta = it->second;

                std::string server_id = meta.name_server;
                std::string origin = meta.origin.has_value()
                    ? *meta.origin
                    : origin_from_filename(p);

                tasks.push_back(Task{p, server_id, origin});
            } else {
                std::cerr << "Warning: No metadata entry for " << fname
                          << " in " << parent << "\n";
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Filesystem error: " << e.what() << "\n";
        delete prog;
        return 1;
    }

    std::cout << ">>> Processing " << tasks.size() << " files...\n";

    auto start_time = std::chrono::high_resolution_clock::now();
    std::mutex rel_mutex;
    std::atomic<size_t> global_counter(0);

#pragma omp parallel for schedule(dynamic, 20)
    for (size_t i = 0; i < tasks.size(); ++i) {
        if (max_records > 0 &&
            global_counter.load(std::memory_order_relaxed) >= max_records) {
            continue;
        }

        process_file(tasks[i].path,
                     tasks[i].server_id,
                     tasks[i].origin,
                     zone_rel,
                     rel_mutex,
                     global_counter,
                     max_records);
    }

    auto parse_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> parse_diff = parse_end_time - start_time;

    std::cout << ">>> Loaded " << global_counter << " records in "
              << parse_diff.count() << "s. ";
    if (max_records > 0 && global_counter >= max_records) {
        std::cout << "(Limit reached: " << max_records << ")\n";
    } else {
        std::cout << "(All records loaded)\n";
    }

    std::cout << ">>> Verifying...\n";
    prog->run();

    auto verify_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> verify_diff = verify_end_time - parse_end_time;
    std::cout << ">>> Verified in " << verify_diff.count() << "s.\n";

    std::cout << ">>> Writing outputs...\n";
    facts_out_file.close();

    prog->printAll(".");

    delete prog;
    return 0;
}
