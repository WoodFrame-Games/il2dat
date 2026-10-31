#include "codereg.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace hd {

static constexpr u64 kHeapBase = 0x30000000;
static u64 META_REG = 0x3634138;      // переопределяется findMetadataRegistration()
static constexpr u64 CODREG = 0x60000000;
static constexpr u64 PTR_ARR_FAKE = 0x60000100;
static constexpr u64 MOD_FAKE = 0x60001000;
static constexpr u64 NAMES = 0x60010000;
static constexpr u64 MPTR = 0x60020000;
static constexpr u64 GENERIC = 0x60040000;
static constexpr u64 ARR = 0x60000200;
static constexpr u64 SYM = 0x60050000;
static constexpr u64 STR = 0x60090000;
static constexpr u64 BOUND = 0x60080000;
static constexpr u64 GENERIC_BASE_DEF = 0x308D4000;
static constexpr u64 GENERIC_SIZE_DEF = 0xB2F0;
static u64 GENERIC_BASE = GENERIC_BASE_DEF;
static u64 GENERIC_SIZE = GENERIC_SIZE_DEF;

// ---------------------------------------------------------------------------
// поиск Il2CppMetadataRegistration в runtime-образе (без версионных констант)
// ---------------------------------------------------------------------------
namespace {
struct RtReader {
    const EmuResult& res;
    explicit RtReader(const EmuResult& r) : res(r) {}
    bool read(u64 va, u64 n, std::vector<u8>& out) const {
        if (va >= kHeapBase && va + n <= kHeapBase + res.heap.size()) {
            out.assign(res.heap.begin() + (va - kHeapBase), res.heap.begin() + (va - kHeapBase + n));
            return true;
        }
        for (const auto& kv : res.segRange) {
            u64 b = kv.second.first, e = kv.second.second;
            if (va >= b && va + n <= e) {
                const auto& seg = res.segments.at(kv.first);
                out.assign(seg.begin() + (va - b), seg.begin() + (va - b + n));
                return true;
            }
        }
        return false;
    }
    bool mapped(u64 va) const {
        if (va >= kHeapBase && va < kHeapBase + res.heap.size()) return true;
        for (const auto& kv : res.segRange)
            if (va >= kv.second.first && va < kv.second.second) return true;
        return false;
    }
    u64 rq(u64 va) const {
        std::vector<u8> d;
        if (!read(va, 8, d)) return 0;
        return rd64(d.data());
    }
    u32 ru32(u64 va) const {
        std::vector<u8> d;
        if (!read(va, 4, d)) return 0;
        return rd32(d.data());
    }
    std::string cstr(u64 va) const {
        std::string s;
        for (u64 i = 0; i < 256; ++i) {
            std::vector<u8> d;
            if (!read(va + i, 1, d)) break;
            if (d[0] == 0) break;
            s.push_back((char)d[0]);
        }
        return s;
    }
};

std::vector<size_t> findAll(const u8* hay, size_t hn, const u8* needle, size_t nn) {
    std::vector<size_t> out;
    if (nn == 0 || nn > hn) return out;
    const u8* p = hay;
    size_t rem = hn;
    for (;;) {
        const u8* q = (const u8*)std::memchr(p, needle[0], rem);
        if (!q) break;
        size_t off = (size_t)(q - hay);
        if (hn - off >= nn && std::memcmp(q, needle, nn) == 0) out.push_back(off);
        p = q + 1;
        rem = hn - (size_t)(p - hay);
    }
    return out;
}
}  // namespace

static bool looksLikeType(const EmuResult& res, u64 tp, u32& typ) {
    RtReader rt(res);
    std::vector<u8> d;
    if (!rt.read(tp, 12, d)) return false;
    typ = (rd32(d.data() + 8) >> 16) & 0xFF;
    return typ >= 1 && typ <= 0x1F;
}

static u64 findMetadataRegistration(const EmuResult& res, const Metadata& meta) {
    RtReader rt(res);
    // выборка byvalTypeIndex из typeDefinitions
    u64 tdoff = meta.sectionOff[19];
    u64 tdcount = meta.sectionSize[19] / 0x58;
    std::vector<u32> bys;
    u64 step = std::max<u64>(1, tdcount / 64);
    for (u64 T = 0; T < tdcount && bys.size() < 64; T += step) {
        bys.push_back(rd32(meta.blob.data() + tdoff + T * 0x58 + 8));
    }
    if (bys.empty()) return 0;
    u32 maxBy = *std::max_element(bys.begin(), bys.end());

    auto validate = [&](u64 P) -> bool {
        u64 q[16];
        std::vector<u8> d;
        if (!rt.read(P, sizeof(q), d)) return false;
        for (int i = 0; i < 16; ++i) q[i] = rd64(d.data() + i * 8);
        u64 cnt = q[6], arr = q[7];
        if (cnt < 1000 || cnt > 800000 || cnt <= maxBy) return false;
        if (!rt.mapped(arr)) return false;
        // выборочная проверка typePtr[]
        u64 stride = std::max<u64>(1, cnt / 48);
        int good = 0, total = 0;
        for (u64 i = 0; i < cnt; i += stride) {
            std::vector<u8> e;
            if (!rt.read(arr + i * 8, 8, e)) continue;
            u64 tp = rd64(e.data());
            u32 typ = 0;
            ++total;
            if (looksLikeType(res, tp, typ)) ++good;
        }
        if (total < 8 || good * 100 < total * 95) return false;
        // byval-типы должны быть class/valueType (0x11/0x12)
        int ok2 = 0, tot2 = 0;
        for (u32 by : bys) {
            if (by >= cnt) continue;
            std::vector<u8> e;
            if (!rt.read(arr + (u64)by * 8, 8, e)) continue;
            u32 typ = 0;
            ++tot2;
            if (looksLikeType(res, rd64(e.data()), typ) && (typ == 0x11 || typ == 0x12)) ++ok2;
        }
        return tot2 > 0 && ok2 * 100 >= tot2 * 90;
    };

    // сегменты библиотеки
    for (const auto& kv : res.segments) {
        const auto& seg = kv.second;
        u64 base = res.segRange.at(kv.first).first;
        for (size_t i = 0; i + 0x80 <= seg.size(); i += 8) {
            u64 cnt = rd64(seg.data() + i + 48);
            if (cnt < 1000 || cnt > 800000) continue;
            u64 P = base + i;
            if (validate(P)) return P;
        }
    }
    // куча
    const auto& heap = res.heap;
    for (size_t i = 0; i + 0x80 <= heap.size(); i += 8) {
        u64 cnt = rd64(heap.data() + i + 48);
        if (cnt < 1000 || cnt > 800000) continue;
        u64 P = kHeapBase + i;
        if (validate(P)) return P;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// runtime reader (emulated heap + library segments)
// ---------------------------------------------------------------------------


std::vector<u64> findModules(const EmuResult& res, const Metadata& meta) {
    RtReader rt(res);
    std::vector<u64> modules;
    u64 n = meta.imageCount();
    for (u64 i = 0; i < n; ++i) {
        std::string name = meta.imageName((u32)i);
        if (name.empty()) return {};
        std::string needle = name + std::string(1, '\0');
        std::vector<u64> cands;

        // collect string addresses
        std::vector<u64> strAddrs;
        for (const auto& kv : res.segments) {
            const auto& seg = kv.second;
            auto hits = findAll(seg.data(), seg.size(), (const u8*)needle.data(), needle.size());
            for (size_t h : hits) strAddrs.push_back(res.segRange.at(kv.first).first + h);
        }
        // for each string address, find the struct whose +0 == that address
        for (u64 S : strAddrs) {
            u8 pat[8];
            wr64(pat, S);
            for (const auto& kv : res.segments) {
                const auto& seg = kv.second;
                auto hits = findAll(seg.data(), seg.size(), pat, 8);
                for (size_t h : hits) {
                    u64 P = res.segRange.at(kv.first).first + h;
                    u64 cnt = rt.rq(P + 8);
                    u64 ptr = rt.rq(P + 0x10);
                    if (cnt <= 0x20000 && (ptr == 0 || rt.mapped(ptr))) cands.push_back(P);
                }
            }
        }
        std::sort(cands.begin(), cands.end());
        cands.erase(std::unique(cands.begin(), cands.end()), cands.end());
        if (cands.empty()) {
            std::fprintf(stderr, "[mod] no module struct for image %llu (%s)\n", (unsigned long long)i, name.c_str());
            return {};
        }
        // prefer a candidate with a nonzero method count
        u64 chosen = cands[0];
        for (u64 c : cands)
            if (rt.rq(c + 8) > 0) { chosen = c; break; }
        modules.push_back(chosen);
    }
    return modules;
}

// ---------------------------------------------------------------------------
// runtime ELF
// ---------------------------------------------------------------------------
struct PhInfo {
    u64 o, type, flags, po, pv, pf, pm;
};

static std::vector<PhInfo> loadPh(const std::vector<u8>& d) {
    std::vector<PhInfo> ph;
    u64 phoff = rd64(d.data() + 0x20);
    u16 pe = rd16(d.data() + 0x36);
    u16 pn = rd16(d.data() + 0x38);
    for (u16 i = 0; i < pn; ++i) {
        u64 o = phoff + (u64)i * pe;
        PhInfo p;
        p.o = o;
        p.type = rd32(d.data() + o);
        p.flags = rd32(d.data() + o + 4);
        p.po = rd64(d.data() + o + 8);
        p.pv = rd64(d.data() + o + 16);
        p.pf = rd64(d.data() + o + 32);
        p.pm = rd64(d.data() + o + 40);
        ph.push_back(p);
    }
    return ph;
}

bool buildRuntimeElf(const ElfFile& orig, const EmuResult& res, const Metadata& meta,
                     const std::vector<u64>& modules, std::vector<u8>& out) {
    out = orig.data;
    auto ph = loadPh(out);

    // 0) динамически находим MetadataRegistration (без версионных констант)
    {
        u64 mr = findMetadataRegistration(res, meta);
        if (!mr) {
            std::fprintf(stderr, "[codereg] MetadataRegistration not found, fallback %#llx\n",
                         (unsigned long long)META_REG);
        } else {
            META_REG = mr;
            std::printf("[codereg] MetadataRegistration = %#llx\n", (unsigned long long)META_REG);
        }
    }

    // 1) overlay decrypted library segments (skip idx 0,1)
    for (const auto& kv : res.segments) {
        if (kv.first < 2) continue;
        u64 base = res.segRange.at(kv.first).first;
        u64 end = res.segRange.at(kv.first).second;
        const auto& data = kv.second;
        for (const auto& p : ph) {
            if (p.type != 1) continue;
            u64 s = std::max(base, p.pv);
            u64 e = std::min(end, p.pv + p.pf);
            if (s < e)
                std::memcpy(out.data() + p.po + (s - p.pv), data.data() + (s - base), (size_t)(e - s));
        }
    }

    // 2) synthetic segment
    u64 blobSize = (GENERIC - CODREG) + 0x20000ull * 8;
    std::vector<u8> blob((size_t)blobSize, 0);  // zeros: only final fields are written below

    u64 fileoff = (out.size() + 0xfff) & ~0xfffull;
    out.resize(fileoff, 0);
    out.insert(out.end(), blob.begin(), blob.end());

    u16 pe = rd16(out.data() + 0x36);
    u64 phoff = rd64(out.data() + 0x20);
    u64 o12 = phoff + 12 * pe;
    wr32(out.data() + o12, 1);
    wr32(out.data() + o12 + 4, 0);
    wr64(out.data() + o12 + 8, fileoff);
    wr64(out.data() + o12 + 16, CODREG);
    wr64(out.data() + o12 + 24, 0);
    wr64(out.data() + o12 + 32, blob.size());
    wr64(out.data() + o12 + 40, blob.size());
    wr64(out.data() + o12 + 48, 0x1000);

    ph = loadPh(out);
    auto v2o = [&](u64 a, u64& off) -> bool {
        for (const auto& x : ph)
            if (x.type == 1 && a >= x.pv && a < x.pv + x.pm) { off = x.po + (a - x.pv); return true; }
        return false;
    };
    for (u64 a : {META_REG + 0x54, META_REG + 0x64}) {
        u64 off;
        if (v2o(a, off)) wr32(out.data() + off, 0);
    }

    // -----------------------------------------------------------------
    // stage B: real CodeRegistration + symbols + dynamic + Il2CppType fix
    // -----------------------------------------------------------------
    const PhInfo* synth = nullptr;
    for (const auto& x : ph)
        if (x.type == 1 && x.pv == CODREG) synth = &x;
    if (!synth) { std::fprintf(stderr, "[codereg] synthetic segment missing\n"); return false; }
    u64 synthOff = synth->po, synthSize = synth->pf;
    std::vector<u8> sblob((size_t)synthSize, 0);
    memcpy(sblob.data(), out.data() + synthOff, (size_t)synthSize);
    auto sput64 = [&](u64 va, u64 v) { u8 b[8]; wr64(b, v); std::memcpy(sblob.data() + (va - CODREG), b, 8); };
    sput64(CODREG + 0x78, modules.size());
    sput64(CODREG + 0x80, ARR);
    for (size_t i = 0; i < modules.size(); ++i) sput64(ARR + i * 8, modules[i]);

    std::vector<u8> symStr = {0};
    size_t codeNamePos = symStr.size();
    const char* cs = "g_CodeRegistration";
    symStr.insert(symStr.end(), cs, cs + std::strlen(cs) + 1);
    size_t metaNamePos = symStr.size();
    const char* ms = "g_MetadataRegistration";
    symStr.insert(symStr.end(), ms, ms + std::strlen(ms) + 1);
    std::memcpy(sblob.data() + (STR - CODREG), symStr.data(), symStr.size());

    auto writeSym = [&](u64 at, u32 nameOff_, u64 value) {
        u8 b[24] = {0};
        wr32(b, nameOff_);
        b[4] = 0x12;
        b[5] = 0;
        wr16(b + 6, 1);
        wr64(b + 8, value);
        std::memcpy(sblob.data() + (at - CODREG), b, 24);
    };
    writeSym(SYM + 24, (u32)codeNamePos, CODREG);
    writeSym(SYM + 48, (u32)metaNamePos, META_REG);

    std::memcpy(out.data() + synthOff, sblob.data(), sblob.size());

    // dynamic
    const PhInfo* dyn = nullptr;
    for (const auto& x : ph) if (x.type == 2) dyn = &x;
    if (dyn) {
        u64 strRaw = synthOff + (STR - CODREG);
        u64 n = dyn->pf / 16;
        for (u64 i = 0; i < n; ++i) {
            u64 o = dyn->po + i * 16;
            i64 tag = (i64)rd64(out.data() + o);
            u64 val = rd64(out.data() + o + 8);
            (void)val;
            if (tag == 6) wr64(out.data() + o + 8, SYM);
            else if (tag == 5) wr64(out.data() + o + 8, strRaw);
            else if (tag == 7) wr64(out.data() + o, 0x6FFFFF00ull);
            else if (tag == 8) wr64(out.data() + o + 8, 0);
            else if (tag == 2) wr64(out.data() + o + 8, 0);
            else if (tag == 0x17) wr64(out.data() + o, 0x6FFFFF01ull);
            else if (tag == 0x1B) wr64(out.data() + o + 8, 0);
            else if (tag == 0xD) { wr64(out.data() + o, 21); wr64(out.data() + o + 8, BOUND); }
        }
    }

    // Il2CppType fix (reads/writes the runtime file)
    const Metadata& MD = meta;
    u64 tdoff = MD.sectionOff[19];
    u64 tdcount = MD.sectionSize[19] / 0x58;
    u64 mro = 0;
    if (!v2o(META_REG, mro)) { std::fprintf(stderr, "[codereg] no metadata registration\n"); return false; }
    u64 mrf[16];
    for (int i = 0; i < 16; ++i) mrf[i] = rd64(out.data() + mro + i * 8);
    u64 numTypes = mrf[6], tl = mrf[7];
    u64 tlOff = 0;
    if (!v2o(tl, tlOff)) { std::fprintf(stderr, "[codereg] no type table\n"); return false; }
    std::vector<u64> typePtr((size_t)numTypes);
    for (u64 i = 0; i < numTypes; ++i) typePtr[i] = rd64(out.data() + tlOff + i * 8);

    std::map<u64, u64> handleToIdx;
    for (u64 T = 0; T < tdcount; ++T) {
        u32 by = rd32(MD.blob.data() + tdoff + T * 0x58 + 8);
        if (by >= numTypes) continue;
        u64 to = 0;
        if (!v2o(typePtr[by], to)) continue;
        u64 dp = rd64(out.data() + to);
        handleToIdx.emplace(dp, T);
    }

    // выводим GENERIC_BASE/SIZE из data-указателей VAR/MVAR типов
    {
        u64 lo = ~0ull, hi = 0;
        int nvars = 0;
        for (u64 tp : typePtr) {
            u64 to = 0;
            if (!v2o(tp, to)) continue;
            u64 dp = rd64(out.data() + to);
            u32 bits = rd32(out.data() + to + 8);
            u32 typ = (bits >> 16) & 0xFF;
            if (typ == 0x13 || typ == 0x1E) {
                ++nvars;
                if (dp < lo) lo = dp;
                if (dp > hi) hi = dp;
            }
        }
        if (nvars >= 8 && lo != ~0ull && lo >= kHeapBase && hi - lo < 0x400000) {
            u64 base = lo & ~0xFFull;
            u64 size = ((hi - base) + 0x10 + 0xF) & ~0xF;
            if (size >= 0x10 && size <= 0x200000) {
                GENERIC_BASE = base;
                GENERIC_SIZE = size;
                std::printf("[codereg] generic table %#llx..%#llx (%llu bytes, %d vars)\n",
                            (unsigned long long)GENERIC_BASE,
                            (unsigned long long)(GENERIC_BASE + GENERIC_SIZE),
                            (unsigned long long)GENERIC_SIZE, nvars);
            }
        }
    }
    u64 genCount = GENERIC_SIZE / 0x10;
    u64 cls = 0, var = 0;
    for (u64 tp : typePtr) {
        u64 to = 0;
        if (!v2o(tp, to)) continue;
        u64 dp = rd64(out.data() + to);
        u32 bits = rd32(out.data() + to + 8);
        u32 typ = (bits >> 16) & 0xFF;
        if (typ == 0x11 || typ == 0x12) {
            auto it = handleToIdx.find(dp);
            if (it != handleToIdx.end()) { wr64(out.data() + to, it->second); ++cls; }
        } else if (typ == 0x13 || typ == 0x1E) {
            u64 idx = 0;
            if (dp >= GENERIC_BASE && dp < GENERIC_BASE + GENERIC_SIZE) idx = (dp - GENERIC_BASE) / 0x10;
            if (idx >= genCount) idx = 0;
            wr64(out.data() + to, idx);
            ++var;
        }
    }
    std::printf("[codereg] modules=%zu typefix class=%llu var/mvar=%llu\n", modules.size(),
                (unsigned long long)cls, (unsigned long long)var);
    return true;
}

// ---------------------------------------------------------------------------
// method map
// ---------------------------------------------------------------------------
std::string buildMethodMap(const ElfFile& orig, const EmuResult& res, const Metadata& meta,
                           const std::vector<u64>& modules) {
    RtReader rt(res);
    const Metadata& MD = meta;
    u64 tdoff = MD.sectionOff[19];
    u64 mdoff = MD.sectionOff[5];

    std::string out;
    out.reserve(8 * 1024 * 1024);
    char line[512];

    u64 imgCount = meta.imageCount();
    for (u64 i = 0; i < imgCount && i < modules.size(); ++i) {
        std::string imgName = meta.imageName((u32)i);
        u64 imgOff = MD.sectionOff[20] + i * 0x28;
        i64 typeStart = (i32)rd32(MD.blob.data() + imgOff + 8);
        u32 typeCount = rd32(MD.blob.data() + imgOff + 12);
        u64 ptrArr = rt.rq(modules[i] + 0x10);
        u64 ptrCount = rt.rq(modules[i] + 8);

        for (i64 t = typeStart; t < typeStart + (i64)typeCount; ++t) {
            if (t < 0) continue;
            u64 to = tdoff + (u64)t * 0x58;
            u32 nameIdx = rd32(MD.blob.data() + to + 0);
            std::string typeName = meta.str(nameIdx);
            i32 methodStart = (i32)rd32(MD.blob.data() + to + 0x24);
            u16 methodCount = rd16(MD.blob.data() + to + 0x40);

            for (i32 mm = 0; mm < methodCount; ++mm) {
                u64 mo = mdoff + (u64)(methodStart + mm) * 0x24;
                u32 mnIdx = rd32(MD.blob.data() + mo + 0);
                u32 token = rd32(MD.blob.data() + mo + 0x18);
                std::string mname = meta.str(mnIdx);

                u64 idx = token & 0xFFFFFFu;
                u64 ptr = 0;
                if (idx >= 1 && idx <= ptrCount && ptrArr) ptr = rt.rq(ptrArr + (idx - 1) * 8);
                u64 foff = 0;
                bool haveOff = ptr && orig.vaToOff(ptr, foff, true);

                if (haveOff)
                    std::snprintf(line, sizeof(line), "%s\t%llu\t%s\t%s\t0x%08X\t0x%llX\t0x%llx\r\n",
                                  imgName.c_str(), (unsigned long long)i, typeName.c_str(), mname.c_str(),
                                  token, (unsigned long long)ptr, (unsigned long long)foff);
                else
                    std::snprintf(line, sizeof(line), "%s\t%llu\t%s\t%s\t0x%08X\t0x%llX\t\r\n",
                                  imgName.c_str(), (unsigned long long)i, typeName.c_str(), mname.c_str(),
                                  token, (unsigned long long)ptr);
                out += line;
            }
        }
    }
    return out;
}

}  // namespace hd