#include "zip.hpp"

#include <zlib.h>
#include <cstring>

namespace hd {

static bool inflateRaw(const u8* in, size_t inLen, u8* out, size_t outLen) {
    z_stream s;
    std::memset(&s, 0, sizeof(s));
    if (inflateInit2(&s, -15) != Z_OK) return false;
    s.next_in = (Bytef*)in;
    s.avail_in = (uInt)inLen;
    s.next_out = (Bytef*)out;
    s.avail_out = (uInt)outLen;
    int r = inflate(&s, Z_FINISH);
    inflateEnd(&s);
    return r == Z_STREAM_END;
}

bool Zip::open(const std::string& path) {
    if (!readFile(path, data_)) return false;
    if (data_.size() < 22) return false;

    // find EOCD
    size_t eocd = std::string::npos;
    size_t maxBack = data_.size() < 0x10000 + 22 ? data_.size() - 22 : 0x10000;
    for (size_t i = 0; i + 22 <= data_.size() && i <= maxBack; ++i) {
        size_t o = data_.size() - 22 - i;
        if (rd32(data_.data() + o) == 0x06054b50) { eocd = o; break; }
    }
    if (eocd == std::string::npos) return false;

    u64 cdCount = rd16(data_.data() + eocd + 10);
    u64 cdOff = rd32(data_.data() + eocd + 16);

    // ZIP64?
    if (cdOff == 0xFFFFFFFF || cdCount == 0xFFFF) {
        // locate zip64 EOCD locator
        for (size_t i = 0; i + 20 <= eocd; ++i) {
            size_t o = eocd - 20 - (eocd - 20 - i);
            if (rd32(data_.data() + i) == 0x07064b50) {
                u64 z64off = rd64(data_.data() + i + 8);
                if (rd32(data_.data() + z64off) == 0x06064b50) {
                    cdCount = rd64(data_.data() + z64off + 32);
                    cdOff = rd64(data_.data() + z64off + 48);
                }
                break;
            }
        }
    }

    u64 p = cdOff;
    for (u64 i = 0; i < cdCount; ++i) {
        if (p + 46 > data_.size()) break;
        if (rd32(data_.data() + p) != 0x02014b50) break;
        Entry e;
        e.method = rd16(data_.data() + p + 10);
        e.compSize = rd32(data_.data() + p + 20);
        e.uncompSize = rd32(data_.data() + p + 24);
        u16 nameLen = rd16(data_.data() + p + 28);
        u16 extraLen = rd16(data_.data() + p + 30);
        u16 cmtLen = rd16(data_.data() + p + 32);
        e.localOff = rd32(data_.data() + p + 42);
        e.name.assign((const char*)data_.data() + p + 46, nameLen);

        // zip64 extra
        if (e.compSize == 0xFFFFFFFF || e.uncompSize == 0xFFFFFFFF || e.localOff == 0xFFFFFFFF) {
            u64 ep = p + 46 + nameLen;
            u64 end = ep + extraLen;
            while (ep + 4 <= end) {
                u16 tag = rd16(data_.data() + ep);
                u16 sz = rd16(data_.data() + ep + 2);
                if (tag == 0x0001) {
                    u64 q = ep + 4;
                    if (e.uncompSize == 0xFFFFFFFF) { e.uncompSize = rd64(data_.data() + q); q += 8; }
                    if (e.compSize == 0xFFFFFFFF) { e.compSize = rd64(data_.data() + q); q += 8; }
                    if (e.localOff == 0xFFFFFFFF) { e.localOff = rd64(data_.data() + q); q += 8; }
                }
                ep += 4 + sz;
            }
        }
        entries_.push_back(e);
        names_.push_back(e.name);
        p += 46 + nameLen + extraLen + cmtLen;
    }
    return !entries_.empty();
}

bool Zip::has(const std::string& name) const {
    for (const auto& e : entries_)
        if (e.name == name) return true;
    return false;
}

bool Zip::extract(const std::string& name, std::vector<u8>& out) const {
    for (const auto& e : entries_) {
        if (e.name != name) continue;
        u64 lo = e.localOff;
        if (lo + 30 > data_.size()) return false;
        if (rd32(data_.data() + lo) != 0x04034b50) return false;
        u16 nameLen = rd16(data_.data() + lo + 26);
        u16 extraLen = rd16(data_.data() + lo + 28);
        u64 dstart = lo + 30 + nameLen + extraLen;
        if (dstart + e.compSize > data_.size()) return false;

        out.resize((size_t)e.uncompSize);
        if (e.method == 0) {
            std::memcpy(out.data(), data_.data() + dstart, (size_t)e.uncompSize);
            return true;
        }
        if (e.method == 8) {
            return inflateRaw(data_.data() + dstart, (size_t)e.compSize, out.data(), (size_t)e.uncompSize);
        }
        return false;
    }
    return false;
}

bool Zip::extractBySuffix(const std::string& suffix, std::vector<u8>& out, std::string& matched) const {
    for (const auto& e : entries_) {
        if (e.name.size() >= suffix.size() &&
            e.name.compare(e.name.size() - suffix.size(), suffix.size(), suffix) == 0) {
            matched = e.name;
            return extract(e.name, out);
        }
    }
    return false;
}

}  // namespace hd