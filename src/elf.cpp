#include "elf.hpp"

namespace hd {

bool readFile(const std::string& path, std::vector<u8>& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    if (sz < 0) { std::fclose(f); return false; }
    std::fseek(f, 0, SEEK_SET);
    out.resize((size_t)sz);
    size_t got = sz ? std::fread(out.data(), 1, (size_t)sz, f) : 0;
    std::fclose(f);
    out.resize(got);
    return true;
}

bool writeFile(const std::string& path, const std::vector<u8>& in) {
    return writeFile(path, in.data(), in.size());
}

bool writeFile(const std::string& path, const u8* data, size_t len) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    size_t put = len ? std::fwrite(data, 1, len, f) : 0;
    std::fclose(f);
    return put == len;
}

std::vector<u8> readFileOrThrow(const std::string& path) {
    std::vector<u8> v;
    if (!readFile(path, v)) {
        std::fprintf(stderr, "error: cannot read %s\n", path.c_str());
        std::exit(2);
    }
    return v;
}

bool ElfFile::load(const std::string& path) {
    if (!readFile(path, data)) return false;
    parse();
    return true;
}

void ElfFile::parse() {
    ph.clear();
    dyn.clear();
    if (data.size() < 0x40) return;
    phoff = rd64(data.data() + 0x20);
    phentsize = rd16(data.data() + 0x36);
    phnum = rd16(data.data() + 0x38);
    for (u16 i = 0; i < phnum; ++i) {
        u64 o = phoff + (u64)i * phentsize;
        if (o + 56 > data.size()) break;
        Phdr p;
        p.type = rd32(data.data() + o);
        p.flags = rd32(data.data() + o + 4);
        p.offset = rd64(data.data() + o + 8);
        p.vaddr = rd64(data.data() + o + 16);
        p.paddr = rd64(data.data() + o + 24);
        p.filesz = rd64(data.data() + o + 32);
        p.memsz = rd64(data.data() + o + 40);
        p.align = rd64(data.data() + o + 48);
        ph.push_back(p);
    }
    // DT entries
    for (const auto& p : ph) {
        if (p.type != 2) continue;  // PT_DYNAMIC
        u64 o = p.offset;
        for (;;) {
            if (o + 16 > data.size()) break;
            u64 tag = rd64(data.data() + o);
            u64 val = rd64(data.data() + o + 8);
            if (tag == 0) break;
            dyn[tag] = val;
            o += 16;
        }
    }
}

const Phdr* ElfFile::loadForVa(u64 va, bool useMemsz) const {
    for (const auto& p : ph) {
        if (p.type != 1) continue;
        u64 end = useMemsz ? p.vaddr + p.memsz : p.vaddr + p.filesz;
        if (va >= p.vaddr && va < end) return &p;
    }
    return nullptr;
}

bool ElfFile::vaToOff(u64 va, u64& off, bool useMemsz) const {
    const Phdr* p = loadForVa(va, useMemsz);
    if (!p) return false;
    off = p->offset + (va - p->vaddr);
    return true;
}

bool ElfFile::readU32(u64 va, u32& out) const {
    u64 o;
    if (!vaToOff(va, o) || o + 4 > data.size()) return false;
    out = rd32(data.data() + o);
    return true;
}

bool ElfFile::readU64(u64 va, u64& out) const {
    u64 o;
    if (!vaToOff(va, o) || o + 8 > data.size()) return false;
    out = rd64(data.data() + o);
    return true;
}

std::string ElfFile::symName(u32 idx) const {
    u64 sym = dynGet(6, 0);  // DT_SYMTAB
    u64 str = dynGet(5, 0);  // DT_STRTAB
    u64 so, sto;
    if (!sym || !str || !vaToOff(sym, so, false) || !vaToOff(str, sto, false)) return "";
    u64 e = so + (u64)idx * 24;
    if (e + 4 > data.size()) return "";
    u32 name = rd32(data.data() + e);
    u64 s = sto + name;
    if (s >= data.size()) return "";
    size_t end = s;
    while (end < data.size() && data[end] != 0) ++end;
    return std::string((const char*)data.data() + s, (size_t)(end - s));
}

std::vector<u64> ElfFile::parseInitArray() const {
    std::vector<u64> out;
    u64 addr = dynGet(25, 0);  // DT_INIT_ARRAY
    u64 sz = dynGet(27, 0);    // DT_INIT_ARRAYSZ
    if (!addr || !sz) return out;
    for (u64 i = 0; i < sz / 8; ++i) {
        u64 o;
        if (!vaToOff(addr + i * 8, o) || o + 8 > data.size()) break;
        out.push_back(rd64(data.data() + o));
    }
    return out;
}

std::vector<Rela> ElfFile::parseRela(u64 addr, u64 size) const {
    std::vector<Rela> out;
    u64 base;
    if (!addr || !size || !vaToOff(addr, base)) return out;
    u64 cnt = size / 24;
    out.reserve((size_t)cnt);
    for (u64 i = 0; i < cnt; ++i) {
        u64 o = base + i * 24;
        if (o + 24 > data.size()) break;
        Rela r;
        r.offset = rd64(data.data() + o);
        r.info = rd64(data.data() + o + 8);
        r.addend = (i64)rd64(data.data() + o + 16);
        out.push_back(r);
    }
    return out;
}

}  // namespace hd