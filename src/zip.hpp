#pragma once
#include "bytes.hpp"
#include <string>
#include <vector>

namespace hd {

// Minimal ZIP reader (stored + deflate) sufficient for APK extraction.
class Zip {
public:
    bool open(const std::string& path);

    bool has(const std::string& name) const;
    // Extract a single entry by exact name.
    bool extract(const std::string& name, std::vector<u8>& out) const;

    // Extract the first entry whose name ends with `suffix` (e.g.
    // "lib/arm64-v8a/libil2cpp.so"). Returns the matched name.
    bool extractBySuffix(const std::string& suffix, std::vector<u8>& out, std::string& matched) const;

    const std::vector<std::string>& names() const { return names_; }

private:
    struct Entry {
        std::string name;
        u16 method = 0;
        u64 compSize = 0;
        u64 uncompSize = 0;
        u64 localOff = 0;
    };
    std::vector<u8> data_;
    std::vector<Entry> entries_;
    std::vector<std::string> names_;
};

}  // namespace hd