#pragma once
#include "bytes.hpp"
#include <map>

namespace hd {

struct Phdr {
    u32 type = 0;
    u32 flags = 0;
    u64 offset = 0;
    u64 vaddr = 0;
    u64 paddr = 0;
    u64 filesz = 0;
    u64 memsz = 0;
    u64 align = 0;
};

struct Rela {
    u64 offset = 0;
    u64 info = 0;
    i64 addend = 0;
    u32 type() const { return (u32)info; }
    u32 sym() const { return (u32)(info >> 32); }
};

struct ElfFile {
    std::vector<u8> data;
    u64 phoff = 0;
    u16 phentsize = 0;
    u16 phnum = 0;
    std::vector<Phdr> ph;
    std::map<u64, u64> dyn;  // tag -> value (DT_ entries, tag 0 terminates)

    bool load(const std::string& path);
    void parse();

    const Phdr* loadForVa(u64 va, bool useMemsz) const;

    // Convert virtual address to file offset. Returns false when not mapped to file.
    bool vaToOff(u64 va, u64& off, bool useMemsz = true) const;

    // Read a little-endian value located at virtual address va.
    bool readU32(u64 va, u32& out) const;
    bool readU64(u64 va, u64& out) const;

    u64 dynGet(u64 tag, u64 def = 0) const {
        auto it = dyn.find(tag);
        return it == dyn.end() ? def : it->second;
    }

    std::string symName(u32 idx) const;

    std::vector<u64> parseInitArray() const;
    std::vector<Rela> parseRela(u64 addr, u64 size) const;
};

}  // namespace hd