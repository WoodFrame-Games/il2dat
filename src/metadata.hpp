#pragma once
#include "bytes.hpp"
#include "emulator.hpp"

namespace hd {

// Canonical IL2CPP v31 metadata section order (index == header entry index).
struct MetaSectionDef {
    const char* name;
    u32 size;   // expected byte size (0 = empty)
    u32 esz;    // entry size (0 = raw)
};
extern const MetaSectionDef kMetaSections[31];

struct Metadata {
    std::vector<u8> blob;
    u64 sectionOff[31] = {0};
    u64 sectionSize[31] = {0};

    bool load(const std::vector<u8>& data);
    bool loadFromFile(const std::string& path);

    std::string str(u32 idx) const;
    u64 imageCount() const { return sectionSize[20] / 0x28; }
    std::string imageName(u32 i) const;
    u64 typeCount() const { return sectionSize[19] / 0x58; }
    u64 methodCount() const { return sectionSize[5] / 0x24; }
};

// Reconstruct a clean global-metadata.dat from the emulated heap and the
// recorded chunk copies (memcpy dst,src,n).
Metadata buildMetadata(const std::vector<u8>& heap, const std::vector<Chunk>& chunks);

}  // namespace hd