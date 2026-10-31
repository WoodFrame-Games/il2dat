#include "metadata.hpp"
#include <cstdio>

namespace hd {

// index -> (name, size, entry size), exactly as used by the reference builder.
const MetaSectionDef kMetaSections[31] = {
    {"stringLiteral", 0x1f8b0, 8},
    {"stringLiteralData", 0x72c60, 0},
    {"string", 0x182548, 0},
    {"events", 0x5460, 0x18},
    {"properties", 0x485d0, 0x14},
    {"methods", 0x2c7438, 0x24},
    {"parameterDefaultValues", 0x7c68, 0xC},
    {"fieldDefaultValues", 0xb874, 0xC},
    {"fieldAndParameterDefaultValueData", 0x51368, 0},
    {"fieldMarshaledSizes", 0x2a420, 0xC},
    {"parameters", 0xfb6ac, 0xC},
    {"fields", 0x9a2f0, 0xC},
    {"genericParameters", 0xb2f0, 0x10},
    {"genericParameterConstraints", 0x804, 4},
    {"genericContainers", 0x6990, 0x10},
    {"nestedTypes", 0x39ac, 4},
    {"interfaces", 0x37fc, 4},
    {"vtableMethods", 0x869f4, 4},
    {"interfaceOffsets", 0x17df0, 8},
    {"typeDefinitions", 0x10a7e0, 0x58},
    {"images", 0xed8, 0x28},
    {"assemblies", 0x17c0, 0x40},
    {"fieldRefs", 0x12e0, 8},
    {"referencedAssemblies", 0x8f0, 4},
    {"attributeData", 0x9a064, 0},
    {"attributeDataRange", 0x2c768, 8},
    {"unresolvedVirtualCallParameterTypes", 0x884c, 4},
    {"unresolvedVirtualCallParameterRanges", 0x5928, 8},
    {"windowsRuntimeTypeNames", 0, 8},
    {"windowsRuntimeStrings", 0, 0},
    {"exportedTypeDefinitions", 0x26c4, 4},
};

constexpr u64 kHeapBase = 0x30000000;

Metadata buildMetadata(const std::vector<u8>& heap, const std::vector<Chunk>& chunks) {
    Metadata m;

    // --- путь 1: готовый образ метадаты лежит в куче целиком -----------------
    // Заголовок v31 самодостаточен: 8 байт (sanity+version) + 31 пара (offset,size),
    // конец файла = max(offset+size). Поэтому kMetaSections больше не нужен.
    {
        const u8 pat[4] = {0xAF, 0x1B, 0xB1, 0xFA};
        for (size_t i = 0; i + 0x100 < heap.size(); ++i) {
            if (heap[i] != pat[0] || heap[i + 1] != pat[1] || heap[i + 2] != pat[2] || heap[i + 3] != pat[3])
                continue;
            u32 ver = rd32(heap.data() + i + 4);
            if (ver < 31 || ver > 39) continue;
            u64 total = 0;
            bool ok = true;
            for (int s = 0; s < 31; ++s) {
                u32 off = rd32(heap.data() + i + 8 + s * 8);
                u32 sz = rd32(heap.data() + i + 8 + s * 8 + 4);
                if (sz && (off < 0x100 || (u64)off + sz > 0x8000000ull)) { ok = false; break; }
                if (sz) total = std::max<u64>(total, (u64)off + sz);
            }
            if (!ok || total < 0x100000 || total > 0x8000000ull) continue;
            if (i + total > heap.size()) continue;
            m.load(std::vector<u8>(heap.begin() + i, heap.begin() + i + total));
            std::fprintf(stderr, "[meta] image found in heap at %#llx, size=%llu\n",
                         (unsigned long long)i, (unsigned long long)total);
            return m;
        }
    }

    // --- путь 3: секции скопированы il2cpp в отдельные heap-блоки -----------
    // Подбираем для каждой секции чанк: размер кратен размеру записи (kMetaSections[i].esz)
    // и близок к эталонному размеру 0.5.0.7 (в пределах 5%). Сырые секции (esz=0) — по близости.
    {
        std::vector<const Chunk*> pool;
        for (const Chunk& c : chunks) {
            if (c.dst < kHeapBase) continue;
            if (c.dst - kHeapBase + c.n > heap.size()) continue;
            if (c.n < 0x400) continue;
            pool.push_back(&c);
        }
        std::vector<int> pick(31, -1);
        std::vector<bool> used(pool.size(), false);

        // сначала секции с фиксированным размером записи
        for (int i = 0; i < 31; ++i) {
            const MetaSectionDef& s = kMetaSections[i];
            if (s.size == 0 || s.esz == 0) continue;
            int best = -1;
            long long bestd = 1LL << 60;
            for (size_t k = 0; k < pool.size(); ++k) {
                if (used[k]) continue;
                u64 n = pool[k]->n;
                if (n % s.esz) continue;
                long long d = (long long)n - (long long)s.size;
                if (d < 0) d = -d;
                if (d * 100 > (long long)s.size * 5) continue;  // >5%
                if (d < bestd) { bestd = d; best = (int)k; }
            }
            if (best >= 0) { pick[i] = best; used[best] = true; }
        }
        // затем сырые секции — по близости
        for (int i = 0; i < 31; ++i) {
            const MetaSectionDef& s = kMetaSections[i];
            if (s.size == 0 || s.esz != 0 || pick[i] >= 0) continue;
            int best = -1;
            long long bestd = 1LL << 60;
            for (size_t k = 0; k < pool.size(); ++k) {
                if (used[k]) continue;
                long long d = (long long)pool[k]->n - (long long)s.size;
                if (d < 0) d = -d;
                if (d * 100 > (long long)s.size * 10) continue;
                if (d < bestd) { bestd = d; best = (int)k; }
            }
            if (best >= 0) { pick[i] = best; used[best] = true; }
        }

        int matched = 0;
        for (int i = 0; i < 31; ++i) if (pick[i] >= 0) ++matched;
        if (matched >= 25) {
            std::vector<u8> blob(0x100, 0);
            wr32(blob.data(), 0xFAB11BAF);
            wr32(blob.data() + 4, 31);
            u64 pos = blob.size();
            for (int i = 0; i < 31; ++i) {
                u64 off = 0, sz = 0;
                if (pick[i] >= 0) {
                    const Chunk& c = *pool[pick[i]];
                    off = pos;
                    sz = c.n;
                    blob.insert(blob.end(), heap.begin() + (c.dst - kHeapBase),
                                heap.begin() + (c.dst - kHeapBase + c.n));
                    pos += sz;
                    while (pos % 4) { blob.push_back(0); ++pos; }
                }
                wr32(blob.data() + 8 + i * 8, (u32)off);
                wr32(blob.data() + 8 + i * 8 + 4, (u32)sz);
                if (pick[i] >= 0)
                    std::fprintf(stderr, "[meta] %-38s size=%llu (chunk #%d)\n", kMetaSections[i].name,
                                 (unsigned long long)sz, pick[i]);
            }
            m.load(blob);
            if (!m.blob.empty() && m.imageCount() > 0) {
                std::fprintf(stderr, "[meta] assembled from chunks: %zu bytes, images=%llu\n",
                             m.blob.size(), (unsigned long long)m.imageCount());
                return m;
            }
        }
    }

    // --- путь 2 (совместимость): сборка по известным размерам чанков ----------
    std::map<u64, const Chunk*> bySize;
    for (const Chunk& c : chunks) {
        if (c.dst < kHeapBase) continue;
        if (c.dst - kHeapBase + c.n > heap.size()) continue;
        if (!bySize.count(c.n)) bySize[c.n] = &c;
    }

    std::vector<u8> blob(0x100, 0);
    wr32(blob.data(), 0xFAB11BAF);
    wr32(blob.data() + 4, 31);

    u64 pos = blob.size();
    struct Ent { u64 off, size; };
    Ent ent[31] = {};
    for (int i = 0; i < 31; ++i) {
        const MetaSectionDef& s = kMetaSections[i];
        if (s.size == 0) continue;
        auto it = bySize.find(s.size);
        if (it == bySize.end()) {
            std::fprintf(stderr, "[meta] missing chunk size 0x%x for %s\n", s.size, s.name);
            continue;
        }
        const Chunk& c = *it->second;
        ent[i].off = pos;
        ent[i].size = s.size;
        blob.insert(blob.end(), heap.begin() + (c.dst - kHeapBase),
                    heap.begin() + (c.dst - kHeapBase + c.n));
        pos += s.size;
        while (pos % 4) { blob.push_back(0); ++pos; }
    }
    for (int i = 0; i < 31; ++i) {
        wr32(blob.data() + 8 + i * 8, (u32)ent[i].off);
        wr32(blob.data() + 8 + i * 8 + 4, (u32)ent[i].size);
    }

    m.load(blob);
    return m;
}

bool Metadata::load(const std::vector<u8>& data) {
    blob = data;
    if (blob.size() < 0x100) return false;
    if (rd32(blob.data()) != 0xFAB11BAF) return false;
    for (int i = 0; i < 31; ++i) {
        sectionOff[i] = rd32(blob.data() + 8 + i * 8);
        sectionSize[i] = rd32(blob.data() + 8 + i * 8 + 4);
    }
    return true;
}

bool Metadata::loadFromFile(const std::string& path) {
    std::vector<u8> d;
    if (!readFile(path, d)) return false;
    return load(d);
}

std::string Metadata::str(u32 idx) const {
    u64 off = sectionOff[2];
    u64 sz = sectionSize[2];
    if (idx >= sz) return "";
    const u8* p = blob.data() + off + idx;
    const u8* end = blob.data() + off + sz;
    const u8* e = p;
    while (e < end && *e) ++e;
    return std::string((const char*)p, (size_t)(e - p));
}

std::string Metadata::imageName(u32 i) const {
    u64 off = sectionOff[20];
    if (off + (u64)i * 0x28 + 4 > blob.size()) return "";
    u32 nameIdx = rd32(blob.data() + off + i * 0x28);
    return str(nameIdx);
}

}  // namespace hd