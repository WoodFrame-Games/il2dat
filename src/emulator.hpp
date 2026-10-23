#pragma once
#include "bytes.hpp"
#include "elf.hpp"
#include <map>
#include <set>
#include <string>
#include <functional>

struct uc_struct;
typedef struct uc_struct uc_engine;

namespace hd {

struct Chunk {
    u64 src;
    u64 dst;
    u64 n;
};

// Result of running the packer under emulation.
struct EmuResult {
    std::vector<u8> heap;                       // fixed 256 MB heap image
    std::map<int, std::vector<u8>> segments;    // index -> segment bytes
    std::map<int, std::pair<u64, u64>> segRange;  // index -> (base,end)
    std::vector<Chunk> chunks;                  // recorded memcpy(dst,src,n) with n>=0x100
    bool stopped = false;
};

struct EmuOptions {
    // PGL/il2cpp entry (from the target batch). Auto-overridable.
    u64 il2cppInit = 0x1686718;
    // Address whose mprotect() switches the packer into the il2cpp phase.
    u64 initTrigger = 0x3522000;
    // Max wall-clock seconds for the main loop.
    double maxSeconds = 360.0;
    bool verbose = false;
};

class Emulator {
public:
    Emulator(ElfFile& elf, EmuOptions opt);
    ~Emulator();

    // Run the unpacker and produce the post-init memory image.
    EmuResult run();

private:
    ElfFile& elf_;
    EmuOptions opt_;
    uc_engine* uc_ = nullptr;

    static constexpr u64 PAGE = 0x1000;
    // extra regions (mirror of the reference harness)
    static constexpr u64 STACK = 0x70000000, STACK_SIZE = 0x200000;
    static constexpr u64 HEAP = 0x30000000, HEAP_SIZE = 0x10000000;
    static constexpr u64 HAND = 0x60000000, HAND_SIZE = 0x200000;
    static constexpr u64 FILEBUF = 0x40000000, FILEBUF_SIZE = 0x10000000;
    static constexpr u64 TLS = 0x71000000;
    static constexpr u64 TRAP = 0x11111110;

    struct MemFile {
        std::string name;
        std::vector<u8> data;
        u64 pos = 0;
    };

    std::map<u64, std::string> handlerNames_;
    std::map<std::string, int> importCount_;
    std::map<u64, MemFile> openFiles_;
    std::map<int, MemFile> fdTable_;
    int nextFd_ = 3;
    std::vector<u64> pthreadKeys_;
    std::map<u64, int> guardSeen_;
    u64 heapPtr_ = 0;
    u64 fakeClockNs_ = 1700000000000000000ull;
    bool stop_ = false;
    bool doInit_ = false;
    bool verbose_ = false;
    std::vector<Chunk> chunks_;
    std::vector<std::pair<u64, std::pair<u64, u64>>> mapped_;  // (start,end,phdr index)
    int ph5Index_ = -1;
    std::set<u64> seenSizes_;
    double t0_ = 0;

    static bool isTargetChunksComplete(const Emulator& e);

    // setup
    void mapSegments();
    void mapExtra();
    void installHandlers();
    u64 addHandler(const std::string& name);
    void applyRelocations();
    void installHooks();

    // import / syscall emulation
    void doImport(u64 addr);
    void handleSvc(u64 intno);
    u64 readReg(int reg) const;
    void writeReg(int reg, u64 v);
    void setRet(u64 val = 0);
    std::string readStr(u64 addr, u64 maxn = 512) const;

    u64 resolveSymbol(u64 symIdx);

    // helpers
    static u64 pageAlign(u64 x) { return x & ~(PAGE - 1); }
    static u64 pageUp(u64 x) { return (x + PAGE - 1) & ~(PAGE - 1); }
    void runInitArray();
    void mainLoop();

    friend struct EmuHooks;
};

}  // namespace hd