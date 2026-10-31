#include "bytes.hpp"
#include "codereg.hpp"
#include "elf.hpp"
#include "emulator.hpp"
#include "metadata.hpp"
#include "zip.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace hd;

static void usage() {
    std::printf(
        "hypperdump - Hypper Sandbox IL2CPP (PGL armor) metadata / codereg recovery\n"
        "\n"
        "usage:\n"
        "  hypperdump full --out <dir> --apk base.apk --apk split_arm64.apk\n"
        "                  [--seconds N] [--verbose] [--cpp2il <exe>]\n"
        "                  [--il2cpp-init <hex>] [--init-trigger <hex>]\n"
        "  hypperdump full --so <libil2cpp.so> --out <dir> [--seconds N]\n"
        "                  [--segments <dir>]   reuse an existing memory dump\n"
        "                  [--il2cpp-init <hex>] [--init-trigger <hex>]\n"
        "  hypperdump emulate --so <libil2cpp.so> --apk <apk> --out <dir>\n"
        "\n"
        "  --apk may be given several times (base APK + split APK); the tool extracts\n"
        "  lib/arm64-v8a/libil2cpp.so, emulates the PGL unpacker, recovers\n"
        "  global-metadata.dat, builds a runtime ELF with the real CodeRegistration and\n"
        "  writes real_method_pointers.tsv.\n"
        "\n"
        "  --il2cpp-init / --init-trigger override the build-specific PGL entry and\n"
        "  il2cpp-phase trigger addresses (defaults: 0x1688258 / 0x3525000).\n");
}

struct Args {
    std::string cmd, so, out, segments, cpp2il;
    std::vector<std::string> apks;
    double seconds = 360.0;
    bool verbose = false;
    unsigned long long il2cppInit = 0, initTrigger = 0;
};

static bool parseArgs(int argc, char** argv, Args& a) {
    if (argc < 2) return false;
    a.cmd = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string s = argv[i];
        auto val = [&](std::string& dst) {
            if (i + 1 < argc) { dst = argv[++i]; return true; }
            return false;
        };
        if (s == "--apk") { std::string v; if (val(v)) a.apks.push_back(v); continue; }
        if (s == "--so") { val(a.so); continue; }
        if (s == "--out") { val(a.out); continue; }
        if (s == "--segments") { val(a.segments); continue; }
        if (s == "--cpp2il") { val(a.cpp2il); continue; }
        if (s == "--verbose") { a.verbose = true; continue; }
        if (s == "--seconds") { if (i + 1 < argc) a.seconds = std::atof(argv[++i]); continue; }
        if (s == "--il2cpp-init") { if (i + 1 < argc) a.il2cppInit = std::strtoull(argv[++i], nullptr, 0); continue; }
        if (s == "--init-trigger") { if (i + 1 < argc) a.initTrigger = std::strtoull(argv[++i], nullptr, 0); continue; }
        std::fprintf(stderr, "unknown arg: %s\n", s.c_str());
        return false;
    }
    return true;
}

static void dumpSegments(const EmuResult& res, const std::string& outdir) {
    for (const auto& kv : res.segments) {
        int idx = kv.first;
        auto rt = res.segRange.find(idx);
        if (rt == res.segRange.end()) continue;
        char name[160];
        std::snprintf(name, sizeof(name), "%s\\memseg_%02d_%llx_%llx.bin", outdir.c_str(), idx,
                      (unsigned long long)rt->second.first, (unsigned long long)rt->second.second);
        writeFile(name, kv.second);
    }
}

static bool loadEmuResult(const std::string& dir, EmuResult& res) {
    if (!readFile(dir + "\\heap_end.bin", res.heap)) return false;
    {
        FILE* f = std::fopen((dir + "\\chunks.txt").c_str(), "r");
        if (f) {
            unsigned long long s, d, n;
            while (std::fscanf(f, "%llx %llx %llx", &s, &d, &n) == 3) res.chunks.push_back({s, d, n});
            std::fclose(f);
        }
    }
    WIN32_FIND_DATAA fd;
    std::string pat = dir + "\\memseg_*.bin";
    HANDLE h = FindFirstFileA(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    do {
        int idx = -1;
        unsigned long long b = 0, e = 0;
        if (std::sscanf(fd.cFileName, "memseg_%d_%llx_%llx.bin", &idx, &b, &e) == 3) {
            std::vector<u8> d;
            if (readFile(dir + "\\" + fd.cFileName, d)) {
                res.segments[idx] = std::move(d);
                res.segRange[idx] = {(u64)b, (u64)e};
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return true;
}

static EmuResult runEmulator(ElfFile& elf, const Args& a) {
    EmuOptions opt;
    if (a.seconds > 0) opt.maxSeconds = a.seconds;
    if (a.il2cppInit) opt.il2cppInit = a.il2cppInit;
    if (a.initTrigger) opt.initTrigger = a.initTrigger;
    opt.verbose = a.verbose;
    Emulator emu(elf, opt);
    EmuResult res = emu.run();
    std::printf("[emu] done. chunks=%zu stop=%d\n", res.chunks.size(), (int)res.stopped);
    writeFile(a.out + "\\heap_end.bin", res.heap);
    dumpSegments(res, a.out);
    {
        std::string txt;
        char line[64];
        for (const Chunk& c : res.chunks) {
            std::snprintf(line, sizeof(line), "%llx %llx %llx\n", (unsigned long long)c.src,
                          (unsigned long long)c.dst, (unsigned long long)c.n);
            txt += line;
        }
        writeFile(a.out + "\\chunks.txt", (const u8*)txt.data(), txt.size());
    }
    return res;
}

// Pull libil2cpp.so out of one of the supplied APKs (base + split). Returns the
// path of the extracted file, empty on failure.
static std::string resolveInput(Args& a) {
    if (a.apks.empty() && !a.so.empty()) {
        if (a.so.size() > 4 && a.so.compare(a.so.size() - 4, 4, ".apk") == 0) a.apks.push_back(a.so);
        else return a.so;
    }
    for (const std::string& apk : a.apks) {
        Zip z;
        if (!z.open(apk)) { std::fprintf(stderr, "[apk] cannot open %s\n", apk.c_str()); continue; }
        std::vector<u8> so;
        std::string matched;
        if (z.extractBySuffix("lib/arm64-v8a/libil2cpp.so", so, matched) ||
            z.extractBySuffix("libil2cpp.so", so, matched)) {
            std::string dst = a.out + "\\libil2cpp.so";
            if (!writeFile(dst, so)) { std::fprintf(stderr, "[apk] cannot write %s\n", dst.c_str()); return ""; }
            std::printf("[apk] extracted %s (%zu bytes) -> %s\n", matched.c_str(), so.size(), dst.c_str());
            return dst;
        }
    }
    std::fprintf(stderr, "[apk] libil2cpp.so not found in the supplied APKs\n");
    return "";
}

static int cmdFull(Args& a) {
    a.so = resolveInput(a);
    if (a.so.empty()) return 2;
    ElfFile elf;
    if (!elf.load(a.so)) { std::fprintf(stderr, "cannot read %s\n", a.so.c_str()); return 2; }

    EmuResult res;
    if (!a.segments.empty()) {
        if (!loadEmuResult(a.segments, res)) { std::fprintf(stderr, "cannot load %s\n", a.segments.c_str()); return 2; }
        std::printf("[emu] loaded memory image from %s\n", a.segments.c_str());
    } else {
        res = runEmulator(elf, a);
    }

    Metadata meta = buildMetadata(res.heap, res.chunks);
    if (meta.blob.empty() || rd32(meta.blob.data()) != 0xFAB11BAF) {
        std::fprintf(stderr, "[meta] failed to build metadata\n");
        return 3;
    }
    writeFile(a.out + "\\global-metadata.dat", meta.blob);
    std::printf("[meta] size=%zu types=%llu images=%llu methods=%llu\n", meta.blob.size(),
                (unsigned long long)meta.typeCount(), (unsigned long long)meta.imageCount(),
                (unsigned long long)meta.methodCount());

    std::vector<u64> modules = findModules(res, meta);
    std::printf("[mod] modules found: %zu / %llu\n", modules.size(), (unsigned long long)meta.imageCount());
    if (modules.empty()) return 4;

    std::vector<u8> runtimeElf;
    if (!buildRuntimeElf(elf, res, meta, modules, runtimeElf)) return 5;
    writeFile(a.out + "\\libil2cpp.runtime.so", runtimeElf);
    std::printf("[elf] wrote runtime ELF size=%zu\n", runtimeElf.size());

    std::string tsv = buildMethodMap(elf, res, meta, modules);
    writeFile(a.out + "\\real_method_pointers.tsv", (const u8*)tsv.data(), tsv.size());
    size_t lines = 0;
    for (char c : tsv) if (c == '\n') ++lines;
    std::printf("[tsv] wrote real_method_pointers.tsv lines=%zu\n", lines);

    if (!a.cpp2il.empty()) {
        std::string isilDir = a.out + "\\isil_dump";
        WIN32_FIND_DATAA fd;
        std::string isilPat = a.out + "\\isil_dump";
        std::string cmd = "\"" + a.cpp2il + "\" --force-binary-path \"" + a.out +
                          "\\libil2cpp.runtime.so\" --force-metadata-path \"" + a.out +
                          "\\global-metadata.dat\" --output-as isil --output-to \"" + isilDir + "\"";
        std::printf("[cpp2il] %s\n", cmd.c_str());
        int rc = std::system(cmd.c_str());
        std::printf("[cpp2il] exit=%d\n", rc);
    }
    return 0;
}

int main(int argc, char** argv) {
    Args a;
    if (!parseArgs(argc, argv, a)) { usage(); return 1; }
    if (!a.out.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(a.out, ec);
    }

    if (a.cmd == "emulate") {
        a.so = resolveInput(a);
        if (a.so.empty()) return 2;
        ElfFile elf;
        if (!elf.load(a.so)) { std::fprintf(stderr, "cannot read %s\n", a.so.c_str()); return 2; }
        EmuResult res = runEmulator(elf, a);
        Metadata m = buildMetadata(res.heap, res.chunks);
        writeFile(a.out + "\\global-metadata.dat", m.blob);
        std::printf("[meta] size=%zu types=%llu images=%llu methods=%llu\n", m.blob.size(),
                    (unsigned long long)m.typeCount(), (unsigned long long)m.imageCount(),
                    (unsigned long long)m.methodCount());
        return 0;
    }
    if (a.cmd == "full") return cmdFull(a);

    usage();
    return 1;
}