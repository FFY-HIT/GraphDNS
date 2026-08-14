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
#include <unordered_map>
#include <fstream>
#include <optional>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

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
        return (len == 1) ||
               (len == 4 &&
                (s[1] & 0xDF) == 'A' &&
                (s[2] & 0xDF) == 'A' &&
                (s[3] & 0xDF) == 'A');
    }

    if (c0 == 'N') {
        if (len == 2 && (s[1] & 0xDF) == 'S') return true;
        if (len == 4 &&
            (s[1] & 0xDF) == 'S' &&
            (s[2] & 0xDF) == 'E' &&
            (s[3] & 0xDF) == 'C') return true;
        return false;
    }

    if (c0 == 'C') return len == 5;                  // CNAME
    if (c0 == 'S') return len == 3;                  // SOA, SRV
    if (c0 == 'M') return len == 2;                  // MX
    if (c0 == 'T') return len == 3;                  // TXT
    if (c0 == 'P') return len == 3;                  // PTR
    if (c0 == 'D') return len == 2 || len == 5 || len == 6; // DS, DNAME, DNSKEY
    if (c0 == 'R') return len == 5;                  // RRSIG

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
    return p >= end || *p == ';';
}

inline std::string normalize_origin(std::string origin) {
    origin = to_lower_ascii(trim_copy(origin));
    if (!origin.empty() && origin.back() != '.') {
        origin.push_back('.');
    }
    return origin;
}

inline std::string origin_from_filename(const fs::path& path) {
    return normalize_origin(path.stem().string());
}

inline std::string absolutize_name(const std::string& token,
                                   const std::string& current_origin) {
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
    return rrtype == "CNAME" ||
           rrtype == "DNAME" ||
           rrtype == "NS"    ||
           rrtype == "PTR"   ||
           rrtype == "MX"    ||
           rrtype == "SRV";
}

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
    if (p >= line_end) return true;

    const char* arg_start = p;
    while (p < line_end && *p != ';') ++p;

    std::string arg = trim_copy(std::string_view(arg_start, p - arg_start));
    if (!arg.empty()) {
        current_origin = absolutize_name(arg, current_origin);
    }

    return true;
}

// ==========================================
// 3. 文件处理逻辑：生成五元组 ZoneRecord.facts
// 五元组格式：server_id, zone_apex, owner_name, rr_type, rr_data
// ==========================================

void process_file(const fs::path& path,
                  const std::string& server_id,
                  const std::string& file_origin,
                  std::atomic<size_t>& global_counter,
                  size_t max_records) {
    MappedFile mfile(path);
    if (!mfile.is_valid()) return;

    const char* ptr = mfile.data();
    const char* end = ptr + mfile.size();

    std::string current_origin = file_origin;
    std::string fixed_zone = file_origin;
    std::string last_owner = file_origin;

    std::string name_buf;
    std::string data_buf;
    std::string temp_type_str;

    std::vector<std::string> local_lines;
    local_lines.reserve(1000);

    while (ptr < end) {
        const char* line_start = ptr;

        while (ptr < end && *ptr != '\n') ++ptr;

        const char* line_end = ptr;
        if (line_end > line_start && *(line_end - 1) == '\r') --line_end;
        if (ptr < end) ++ptr;

        if (is_blank_or_comment(line_start, line_end)) continue;

        if (handle_origin_directive(line_start, line_end, current_origin)) {
            last_owner = current_origin;
            continue;
        }

        const char* part_ptrs[16];
        size_t part_lens[16];
        int part_count = 0;

        const char* p = line_start;

        while (p < line_end && part_count < 16) {
            while (p < line_end && std::isspace(static_cast<unsigned char>(*p))) ++p;
            if (p >= line_end || *p == ';') break;

            const char* token_start = p;
            while (p < line_end &&
                   !std::isspace(static_cast<unsigned char>(*p)) &&
                   *p != ';') {
                ++p;
            }

            part_ptrs[part_count] = token_start;
            part_lens[part_count] = static_cast<size_t>(p - token_start);
            ++part_count;
        }

        if (part_count < 2) continue;

        int type_idx = -1;
        for (int i = 0; i < part_count && i < 5; ++i) {
            if (is_rr_type_fast(part_ptrs[i], part_lens[i])) {
                type_idx = i;
                break;
            }
        }

        if (type_idx == -1) continue;

        size_t current_count = global_counter.load(std::memory_order_relaxed);
        if (max_records > 0 && current_count >= max_records) break;

        size_t new_count = global_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        if (max_records > 0 && new_count > max_records) {
            global_counter.fetch_sub(1, std::memory_order_relaxed);
            break;
        }

        if (type_idx == 0) {
            name_buf = last_owner;
        } else {
            std::string raw_owner = clean_domain_copy(part_ptrs[0], part_lens[0]);
            name_buf = absolutize_name(raw_owner, current_origin);
            last_owner = name_buf;
        }

        temp_type_str.assign(part_ptrs[type_idx], part_lens[type_idx]);
        for (auto& c : temp_type_str) {
            if (c >= 'a' && c <= 'z') c -= 0x20;
        }

        const char* data_ptr = part_ptrs[type_idx] + part_lens[type_idx];
        while (data_ptr < line_end &&
               std::isspace(static_cast<unsigned char>(*data_ptr))) {
            ++data_ptr;
        }

        const char* real_end = line_end;
        while (real_end > data_ptr &&
               std::isspace(static_cast<unsigned char>(*(real_end - 1)))) {
            --real_end;
        }

        data_buf = normalize_rdata(temp_type_str, data_ptr, real_end, current_origin);

        std::string out;
        out.reserve(server_id.size() + fixed_zone.size() + name_buf.size() +
                    temp_type_str.size() + data_buf.size() + 16);

        out += server_id;
        out += '\t';
        out += fixed_zone;
        out += '\t';
        out += name_buf;
        out += '\t';
        out += temp_type_str;
        out += '\t';
        out += data_buf;
        out += '\n';

        local_lines.push_back(std::move(out));

        if (local_lines.size() >= 1000) {
            std::lock_guard<std::mutex> lock(facts_mutex);
            for (const auto& line : local_lines) {
                facts_out_file << line;
            }
            local_lines.clear();
        }
    }

    if (!local_lines.empty()) {
        std::lock_guard<std::mutex> lock(facts_mutex);
        for (const auto& line : local_lines) {
            facts_out_file << line;
        }
    }
}

// ==========================================
// 4. 主函数
// ==========================================

struct FileMeta {
    std::string name_server;
    std::optional<std::string> origin;
};

struct Task {
    fs::path path;
    std::string server_id;
    std::string origin;
};

int main(int argc, char** argv) {
    size_t max_records = 0;

    if (argc < 2) {
        std::cerr << "Usage: ./preprocess <dataset_directory> [max_records]\n";
        std::cerr << "Example: ./preprocess ./data 1000000\n";
        std::cerr << "         ./preprocess ./data\n";
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

    facts_out_file.open("ZoneRecord.facts", std::ios::out | std::ios::trunc);
    if (!facts_out_file.is_open()) {
        std::cerr << "Error: Could not open ZoneRecord.facts\n";
        return 1;
    }

    std::cout << ">>> Scanning files...\n";

    std::vector<Task> tasks;
    tasks.reserve(10000);

    std::unordered_map<fs::path, std::unordered_map<std::string, FileMeta>> dir_to_file_meta;

    try {
        fs::directory_options scan_options =
            fs::directory_options::follow_directory_symlink |
            fs::directory_options::skip_permission_denied;
        for (const auto& entry : fs::recursive_directory_iterator(root_dir, scan_options)) {
            if (!entry.is_regular_file()) continue;

            const auto& p = entry.path();
            if (p.extension() != ".txt") continue;

            fs::path parent = p.parent_path();

            if (dir_to_file_meta.find(parent) == dir_to_file_meta.end()) {
                fs::path meta_path = parent / "metadata.json";

                if (!fs::exists(meta_path)) {
                    std::cerr << "Warning: No metadata.json in " << parent << "\n";
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
                        meta.name_server = normalize_origin(zf["NameServer"].get<std::string>());

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

                std::string server_id = normalize_origin(meta.name_server);
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
        facts_out_file.close();
        std::cerr << "Filesystem error: " << e.what() << "\n";
        return 1;
    }

    std::cout << ">>> Processing " << tasks.size() << " files...\n";

    auto start_time = std::chrono::high_resolution_clock::now();

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
                     global_counter,
                     max_records);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;

    facts_out_file.close();

    std::cout << ">>> Loaded " << global_counter << " records in "
              << diff.count() << "s. ";

    if (max_records > 0 && global_counter >= max_records) {
        std::cout << "(Limit reached: " << max_records << ")\n";
    } else {
        std::cout << "(All records loaded)\n";
    }

    std::cout << ">>> Output: ZoneRecord.facts\n";

    return 0;
}
