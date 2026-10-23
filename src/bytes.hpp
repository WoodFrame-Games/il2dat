#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cstdio>

namespace hd {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i32 = int32_t;
using i64 = int64_t;

inline u16 rd16(const u8* p) { return (u16)p[0] | ((u16)p[1] << 8); }
inline u32 rd32(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
inline u64 rd64(const u8* p) {
    return (u64)rd32(p) | ((u64)rd32(p + 4) << 32);
}
inline void wr16(u8* p, u16 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
inline void wr32(u8* p, u32 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24); }
inline void wr64(u8* p, u64 v) { wr32(p, (u32)v); wr32(p + 4, (u32)(v >> 32)); }

struct Buf {
    const u8* d = nullptr;
    size_t n = 0;
    Buf() = default;
    Buf(const u8* p, size_t sz) : d(p), n(sz) {}
    u8 at(size_t i) const { return d[i]; }
    u64 u32at(size_t i) const { return rd32(d + i); }
    u64 u64at(size_t i) const { return rd64(d + i); }
};

bool readFile(const std::string& path, std::vector<u8>& out);
bool writeFile(const std::string& path, const std::vector<u8>& in);
bool writeFile(const std::string& path, const u8* data, size_t len);

std::vector<u8> readFileOrThrow(const std::string& path);

inline std::string hex(u64 v) {
    char b[32];
    std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v);
    return b;
}

}  // namespace hd