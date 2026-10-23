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
    // index chunks by size (dst copy already applied to heap)
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

    Metadata m;
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