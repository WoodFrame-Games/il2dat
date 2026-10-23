#include "emulator.hpp"

#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>

#include <chrono>
#include <cstdio>
#include <cstring>

namespace hd {

// ---------------------------------------------------------------------------
// static tables mirrored from the reference harness (per-device props etc.)
// ---------------------------------------------------------------------------
static const char* kStatus =
    "Name:\thypper\nUmask:\t0022\nState:\tR (running)\nTgid:\t1234\nNgid:\t0\nPid:\t1234\nPPid:\t1\n"
    "TracerPid:\t0\nUid:\t10123\t10123\t10123\t10123\nGid:\t10123\t10123\t10123\t10123\nFDSize:\t256\n"
    "Groups:\t3003 9997 20123 50123\nVmPeak:\t 3145728 kB\nVmSize:\t 2097152 kB\nVmLck:\t       0 kB\n"
    "VmPin:\t       0 kB\nVmHWM:\t  524288 kB\nVmRSS:\t  419430 kB\nRssAnon:\t  262144 kB\nRssFile:\t  131072 kB\n"
    "RssShmem:\t   16384 kB\nVmData:\t  524288 kB\nVmStk:\t     132 kB\nVmExe:\t   32768 kB\nVmLib:\t  131072 kB\n"
    "VmPTE:\t    2048 kB\nVmSwap:\t       0 kB\nCoreDumping:\t0\nTHP_enabled:\t1\nThreads:\t8\n"
    "SigQ:\t0/12345\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000001204\n"
    "SigIgn:\t0000000000000000\nSigCgt:\t00000001800044e8\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
    "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n"
    "Seccomp:\t0\nSeccomp_filters:\t0\nSpeculation_Store_Bypass:\tnot vulnerable\nCpus_allowed:\tff\n"
    "Cpus_allowed_list:\t0-7\nMems_allowed:\t1\nMems_allowed_list:\t0\nvoluntary_ctxt_switches:\t42\n"
    "nonvoluntary_ctxt_switches:\t7\n";

static const u32 kTargetSizes[] = {
    0x188, 0x6990, 0xfb6ac, 0x2c768, 0xed8, 0x2a420, 0xb874, 0x804, 0x869f4, 0x5928,
    0x17c0, 0x8f0, 0x884c, 0x39ac, 0x51368, 0x12e0, 0x9a2f0, 0x485d0, 0x72c60, 0x17df0,
    0x10a7e0, 0x37fc, 0x5460, 0x2c7438, 0xb2f0, 0x1f8b0, 0x182548, 0x7c68, 0x9a064, 0x26c4};

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------
struct EmuHooks {
    static void code(uc_engine* uc, uint64_t address, uint32_t, void* ud) {
        Emulator* e = (Emulator*)ud;
        if (address >= Emulator::HAND && address < Emulator::HAND + Emulator::HAND_SIZE)
            e->doImport(address);
    }
    static void intr(uc_engine* uc, uint32_t intno, void* ud) {
        ((Emulator*)ud)->handleSvc(intno);
    }
    static bool unmapped(uc_engine* uc, int access, uint64_t address, int size, int64_t value, void* ud) {
        Emulator* e = (Emulator*)ud;
        if (access == UC_MEM_FETCH_UNMAPPED || access == UC_MEM_FETCH_PROT) {
            if (e->verbose_)
                std::fprintf(stderr, "[emu] fetch-unmapped pc=%s addr=%s -> stop\n",
                             hex(e->readReg(UC_ARM64_REG_PC)).c_str(), hex(address).c_str());
            e->stop_ = true;
            uc_emu_stop(uc);
            return false;
        }
        // map a fresh page and continue
        u64 base = Emulator::pageAlign(address);
        if (uc_mem_map(uc, base, Emulator::PAGE, UC_PROT_ALL) == UC_ERR_OK) return true;
        return false;
    }
    static bool wprot(uc_engine* uc, int, uint64_t address, int size, int64_t, void* ud) {
        Emulator* e = (Emulator*)ud;
        u64 a = Emulator::pageAlign(address);
        u64 b = Emulator::pageUp(address + (size > 0 ? size : 1));
        if (e->verbose_) std::fprintf(stderr, "[emu] write-prot %s -> relax\n", hex(address).c_str());
        return uc_mem_protect(uc, a, b - a, UC_PROT_ALL) == UC_ERR_OK;
    }
};

Emulator::Emulator(ElfFile& elf, EmuOptions opt) : elf_(elf), opt_(opt) { verbose_ = opt.verbose; }
Emulator::~Emulator() { if (uc_) uc_close(uc_); }

u64 Emulator::readReg(int reg) const {
    u64 v = 0;
    uc_reg_read(uc_, reg, &v);
    return v;
}
void Emulator::writeReg(int reg, u64 v) { uc_reg_write(uc_, reg, &v); }

void Emulator::setRet(u64 val) {
    writeReg(UC_ARM64_REG_X0, val);
    writeReg(UC_ARM64_REG_PC, readReg(UC_ARM64_REG_LR));
}

std::string Emulator::readStr(u64 addr, u64 maxn) const {
    std::string out;
    for (u64 i = 0; i < maxn; ++i) {
        u8 b = 0;
        if (uc_mem_read(uc_, addr + i, &b, 1) != UC_ERR_OK) break;
        if (b == 0) break;
        out.push_back((char)b);
    }
    return out;
}

u64 Emulator::addHandler(const std::string& name) {
    u64 addr = HAND + (u64)handlerNames_.size() * 4;
    handlerNames_[addr] = name;
    return addr;
}

void Emulator::mapSegments() {
    for (size_t i = 0; i < elf_.ph.size(); ++i) {
        const Phdr& s = elf_.ph[i];
        if (s.type != 1) continue;
        u64 start = pageAlign(s.vaddr);
        u64 end = pageUp(s.vaddr + s.memsz);
        if (end <= start) continue;
        int perm = 0;
        if (s.flags & 4) perm |= UC_PROT_READ;
        if (s.flags & 2) perm |= UC_PROT_WRITE;
        if (s.flags & 1) perm |= UC_PROT_EXEC;
        uc_err err = uc_mem_map(uc_, start, end - start, perm);
        if (err != UC_ERR_OK) {
            std::fprintf(stderr, "[emu] map fail %s..%s err=%d\n", hex(start).c_str(), hex(end).c_str(), (int)err);
            continue;
        }
        if (s.filesz) uc_mem_write(uc_, s.vaddr, elf_.data.data() + s.offset, s.filesz);
        mapped_.push_back({start, {end, (u64)i}});
        if (s.vaddr == 0x3b68000) ph5Index_ = (int)mapped_.size() - 1;
    }
}

void Emulator::mapExtra() {
    const std::pair<u64, u64> regions[] = {
        {STACK, STACK_SIZE}, {HEAP, HEAP_SIZE}, {HAND, HAND_SIZE}, {FILEBUF, FILEBUF_SIZE}, {TLS, 0x10000}};
    for (auto& r : regions) uc_mem_map(uc_, r.first, r.second, UC_PROT_ALL);

    u64 marker = 0xdeadbeef;
    uc_mem_write(uc_, TLS + 0x28, &marker, 8);
    writeReg(UC_ARM64_REG_TPIDR_EL0, TLS);
    writeReg(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x1000);
    writeReg(UC_ARM64_REG_LR, TRAP);
}

void Emulator::installHandlers() {
    std::vector<u8> buf(HAND_SIZE);
    for (u64 i = 0; i < HAND_SIZE; i += 4) wr32(buf.data() + i, 0xD65F03C0);
    uc_mem_write(uc_, HAND, buf.data(), HAND_SIZE);
}

u64 Emulator::resolveSymbol(u64 symIdx) {
    u64 symtab = elf_.dynGet(6, 0);
    u64 so = 0;
    if (!symtab || !elf_.vaToOff(symtab, so, false)) return addHandler("?");
    u64 e = so + symIdx * 24;
    if (e + 24 > elf_.data.size()) return addHandler("?");
    u16 shndx = rd16(elf_.data.data() + e + 6);
    if (shndx != 0) return rd64(elf_.data.data() + e + 8);
    return addHandler(elf_.symName((u32)symIdx));
}

void Emulator::applyRelocations() {
    auto rela = elf_.parseRela(elf_.dynGet(7, 0), elf_.dynGet(8, 0));
    for (const Rela& r : rela) {
        u32 typ = r.type();
        u32 sym = r.sym();
        u64 val;
        if (typ == 1027) val = (u64)r.addend;
        else if (typ == 1025 || typ == 1026 || typ == 257) val = resolveSymbol(sym);
        else if (typ == 1032) val = 0;
        else if (typ == 0) continue;
        else val = (u64)r.addend;
        uc_mem_write(uc_, r.offset, &val, 8);
    }
    // rela.plt -> jump slots point at import handlers
    u64 jmprel = elf_.dynGet(23, 0), jmprelsz = elf_.dynGet(2, 0);
    u64 base = 0;
    if (jmprel && jmprelsz && elf_.vaToOff(jmprel, base)) {
        u64 cnt = jmprelsz / 24;
        for (u64 i = 0; i < cnt; ++i) {
            u64 o = base + i * 24;
            if (o + 16 > elf_.data.size()) break;
            u64 off = rd64(elf_.data.data() + o);
            u64 sym = rd64(elf_.data.data() + o + 8) >> 32;
            u64 a = addHandler(elf_.symName((u32)sym));
            uc_mem_write(uc_, off, &a, 8);
        }
    }
}

void Emulator::installHooks() {
    uc_hook h;
    uc_hook_add(uc_, &h, UC_HOOK_CODE, (void*)EmuHooks::code, this, (u64)HAND, (u64)(HAND + HAND_SIZE));
    uc_hook_add(uc_, &h, UC_HOOK_INTR, (void*)EmuHooks::intr, this, (u64)0, (u64)0);
    uc_hook_add(uc_, &h, UC_HOOK_MEM_UNMAPPED, (void*)EmuHooks::unmapped, this, (u64)0, (u64)0);
    uc_hook_add(uc_, &h, UC_HOOK_MEM_WRITE_PROT, (void*)EmuHooks::wprot, this, (u64)0, (u64)0);
}

// ---------------------------------------------------------------------------
// imports (PLS-style)
// ---------------------------------------------------------------------------
void Emulator::doImport(u64 addr) {
    auto it = handlerNames_.find(addr);
    const std::string name = it == handlerNames_.end() ? std::string("?") : it->second;
    int& cnt = importCount_[name];
    ++cnt;
    if (verbose_ && cnt <= 1)
        std::fprintf(stderr, "[emu] import %s\n", name.c_str());

    u64 a0 = readReg(UC_ARM64_REG_X0), a1 = readReg(UC_ARM64_REG_X1), a2 = readReg(UC_ARM64_REG_X2);

    auto bump = [&](u64 n) {
        u64 a = HEAP + heapPtr_;
        heapPtr_ += ((n + 0x1000) & ~0xFFFull) + 0x1000;
        return a;
    };

    if (name == "malloc") { setRet(bump(a0)); return; }
    if (name == "calloc") {
        u64 n = a0 * a1;
        u64 a = bump(n);
        std::vector<u8> z((size_t)n, 0);
        if (n) uc_mem_write(uc_, a, z.data(), n);
        setRet(a);
        return;
    }
    if (name == "free") { setRet(0); return; }
    if (name == "memset") {
        u64 dst = a0, c = a1, n = a2;
        if (n) {
            std::vector<u8> z((size_t)n, (u8)(c & 0xff));
            uc_mem_write(uc_, dst, z.data(), n);
        }
        setRet(dst);
        return;
    }
    if (name == "memcpy" || name == "memmove") {
        u64 dst = a0, src = a1, n = a2;
        std::vector<u8> data((size_t)n);
        if (n) {
            if (uc_mem_read(uc_, src, data.data(), n) == UC_ERR_OK) {
                uc_mem_write(uc_, dst, data.data(), n);
                if (n >= 0x100) { chunks_.push_back({src, dst, n}); seenSizes_.insert(n); }
            }
        }
        setRet(dst);
        return;
    }
    if (name == "dladdr") {
        u64 info = a1;
        u64 p = FILEBUF + 0x800000;
        std::string s = "libil2cpp.so";
        uc_mem_write(uc_, p, s.c_str(), s.size() + 1);
        u64 q[4] = {p, 0, 0, 0};
        uc_mem_write(uc_, info, q, 32);
        setRet(1);
        return;
    }
    if (name == "sysconf") { setRet(0x1000); return; }
    if (name == "getpid") { setRet(1234); return; }
    if (name == "__android_log_print") { setRet(0); return; }
    if (name == "fopen") {
        std::string p = readStr(a0), mode = readStr(a1);
        std::vector<u8> data;
        if (p.size() >= 12 && p.compare(p.size() - 12, 12, "libil2cpp.so") == 0) data = elf_.data;
        else if (p.find("global-metadata.dat") != std::string::npos) {
            if (ph5Index_ >= 0) {
                u64 b = mapped_[ph5Index_].first, e = mapped_[ph5Index_].second.first;
                data.resize((size_t)(e - b));
                uc_mem_read(uc_, b, data.data(), e - b);
            }
        } else if (p.find("status") != std::string::npos) {
            data.assign((const u8*)kStatus, (const u8*)kStatus + std::strlen(kStatus));
        } else if (p.find("maps") != std::string::npos) {
            data.clear();
        } else if (p.find("cmdline") != std::string::npos) {
            const char* c = "com.Hypper";
            data.assign((const u8*)c, (const u8*)c + std::strlen(c) + 1);
        }
        u64 fp = FILEBUF + openFiles_.size() * 0x100000;
        MemFile f; f.name = p; f.data = std::move(data); f.pos = 0;
        openFiles_[fp] = std::move(f);
        setRet(fp);
        return;
    }
    if (name == "fclose") { setRet(0); return; }
    if (name == "fgets") {
        u64 buf = a0, sz = a1, fp = a2;
        auto fi = openFiles_.find(fp);
        if (fi == openFiles_.end()) { setRet(0); return; }
        MemFile& f = fi->second;
        size_t nl = f.data.size();
        for (size_t i = (size_t)f.pos; i < f.data.size(); ++i)
            if (f.data[i] == '\n') { nl = i + 1; break; }
        if (nl <= f.pos) { setRet(0); return; }
        size_t len = nl - (size_t)f.pos;
        if (sz > 0 && len > sz - 1) len = sz - 1;
        uc_mem_write(uc_, buf, f.data.data() + f.pos, len);
        u8 z = 0;
        uc_mem_write(uc_, buf + len, &z, 1);
        f.pos += len;
        setRet(buf);
        return;
    }
    if (name == "read") {
        u64 fd = a0, buf = a1, n = a2;
        auto it2 = fdTable_.find((int)fd);
        if (it2 == fdTable_.end()) { setRet(0); return; }
        MemFile& f = it2->second;
        size_t avail = f.data.size() - (size_t)f.pos;
        size_t take = n < avail ? (size_t)n : avail;
        if (take) { uc_mem_write(uc_, buf, f.data.data() + f.pos, take); f.pos += take; }
        setRet(take);
        return;
    }
    if (name == "strlen") { setRet(readStr(a0, 1 << 20).size()); return; }
    if (name == "strcmp") {
        std::string x = readStr(a0), y = readStr(a1);
        setRet(x < y ? (u64)-1 : (x > y ? 1 : 0));
        return;
    }
    if (name == "strncmp") {
        std::string x = readStr(a0, a2 < 256 ? a2 : 256), y = readStr(a1, a2 < 256 ? a2 : 256);
        setRet(x < y ? (u64)-1 : (x > y ? 1 : 0));
        return;
    }
    if (name == "getauxval") {
        u64 t = a0;
        switch (t) {
            case 3: setRet(0x40); return;
            case 4: setRet(0x38); return;
            case 5: setRet(11); return;
            case 6: setRet(0x1000); return;
            case 9: setRet(elf_.dynGet(12, 0)); return;
            case 11: case 12: case 13: case 14: setRet(10123); return;
            case 16: setRet(0x3); return;
            case 17: setRet(100); return;
            case 51: setRet(0x2000); return;
            case 15: {
                u64 p = FILEBUF + 0x900000 + 15 * 0x100;
                const char* s = "aarch64";
                uc_mem_write(uc_, p, s, 8);
                setRet(p);
                return;
            }
            case 25: {
                u64 p = FILEBUF + 0x900000 + 25 * 0x100;
                u8 w[16];
                for (int i = 0; i < 16; ++i) w[i] = (u8)i;
                uc_mem_write(uc_, p, w, 16);
                setRet(p);
                return;
            }
            case 31: {
                u64 p = FILEBUF + 0x900000 + 31 * 0x100;
                const char* s = "com.Hypper";
                uc_mem_write(uc_, p, s, 12);
                setRet(p);
                return;
            }
            default: setRet(0); return;
        }
    }
    if (name == "__system_property_get") {
        static const std::pair<const char*, const char*> props[] = {
            {"ro.build.version.sdk", "33"}, {"ro.build.version.release", "13"},
            {"ro.product.cpu.abi", "arm64-v8a"}, {"ro.product.cpu.abilist", "arm64-v8a,armeabi-v7a,armeabi"},
            {"ro.debuggable", "0"}, {"ro.secure", "1"}, {"ro.build.tags", "release-keys"},
            {"ro.build.type", "user"}, {"ro.product.model", "Pixel 7"}, {"ro.product.brand", "google"},
            {"ro.hardware", "qcom"}, {"ro.board.platform", "tensor"}, {"ro.arch", "arm64"},
            {"ro.kernel.qemu", "0"}, {"ro.boot.qemu", "0"}, {"ro.product.manufacturer", "Google"}};
        std::string k = readStr(a0);
        const char* v = "";
        for (auto& p : props)
            if (k == p.first) { v = p.second; break; }
        size_t len = std::strlen(v);
        uc_mem_write(uc_, a1, v, len + 1);
        setRet(len);
        return;
    }
    if (name == "clock_gettime") {
        fakeClockNs_ += 1000;
        u64 sec = fakeClockNs_ / 1000000000ull, nsec = fakeClockNs_ % 1000000000ull;
        u64 ts[2] = {sec, nsec};
        uc_mem_write(uc_, a1, ts, 16);
        setRet(0);
        return;
    }
    if (name == "_Znwm" || name == "_Znam") { setRet(bump(a0)); return; }
    if (name == "realloc") {
        u64 p = a0, n = a1;
        u64 a = bump(n);
        if (p) {
            size_t take = (size_t)(n < 0x10000 ? n : 0x10000);
            std::vector<u8> d(take);
            if (uc_mem_read(uc_, p, d.data(), take) == UC_ERR_OK) uc_mem_write(uc_, a, d.data(), take);
        }
        setRet(a);
        return;
    }
    if (name == "__cxa_guard_acquire") {
        u64 g = a0;
        int v = guardSeen_.count(g) ? 0 : 1;
        guardSeen_[g] = 1;
        setRet(v);
        return;
    }
    if (name == "__cxa_guard_release" || name == "__cxa_guard_abort") { setRet(0); return; }
    if (name == "pthread_key_create") {
        u32 v = 0x100 + (u32)pthreadKeys_.size();
        uc_mem_write(uc_, a0, &v, 4);
        pthreadKeys_.push_back(a0);
        setRet(0);
        return;
    }
    if (name == "pthread_mutex_init") {
        std::vector<u8> z(64, 0);
        uc_mem_write(uc_, a0, z.data(), 64);
        setRet(0);
        return;
    }
    if (name.rfind("pthread_", 0) == 0) { setRet(0); return; }
    if (name == "__stack_chk_fail") { stop_ = true; return; }
    if (name == "abort" || name == "exit") { stop_ = true; return; }
    setRet(0);
}

// ---------------------------------------------------------------------------
// syscalls
// ---------------------------------------------------------------------------
void Emulator::handleSvc(u64 intno) {
    if (intno != 2) return;
    u64 x8 = readReg(UC_ARM64_REG_X8);
    u64 a0 = readReg(UC_ARM64_REG_X0), a1 = readReg(UC_ARM64_REG_X1), a2 = readReg(UC_ARM64_REG_X2);
    u64 a3 = readReg(UC_ARM64_REG_X3), a4 = readReg(UC_ARM64_REG_X4), a5 = readReg(UC_ARM64_REG_X5);
    u64 r = 0;

    auto bump = [&](u64 n) {
        u64 a = HEAP + heapPtr_;
        heapPtr_ += ((n + 0x1000) & ~0xFFFull) + 0x1000;
        return a;
    };

    if (x8 == 56) {  // openat
        std::string p = readStr(a1);
        std::vector<u8> data;
        if (p.find("global-metadata") != std::string::npos ||
            (p.size() >= 4 && p.compare(p.size() - 4, 4, ".dat") == 0)) {
            if (ph5Index_ >= 0) {
                u64 b = mapped_[ph5Index_].first, e = mapped_[ph5Index_].second.first;
                data.resize((size_t)(e - b));
                uc_mem_read(uc_, b, data.data(), e - b);
            }
        } else if (p.size() >= 12 && p.compare(p.size() - 12, 12, "libil2cpp.so") == 0) {
            data = elf_.data;
        } else if (p.find("status") != std::string::npos) {
            data.assign((const u8*)kStatus, (const u8*)kStatus + std::strlen(kStatus));
        } else {
            data.clear();
        }
        int fd = nextFd_++;
        MemFile f; f.name = p; f.data = std::move(data); f.pos = 0;
        fdTable_[fd] = std::move(f);
        r = (u64)fd;
    } else if (x8 == 57) {  // close
        fdTable_.erase((int)a0);
        r = 0;
    } else if (x8 == 63) {  // read
        auto it = fdTable_.find((int)a0);
        if (it != fdTable_.end()) {
            MemFile& f = it->second;
            size_t avail = f.data.size() - (size_t)f.pos;
            size_t take = a2 < avail ? (size_t)a2 : avail;
            if (take) { uc_mem_write(uc_, a1, f.data.data() + f.pos, take); f.pos += take; }
            r = take;
        }
    } else if (x8 == 64) {  // write
        r = a2;
    } else if (x8 == 62) {  // lseek
        auto it = fdTable_.find((int)a0);
        if (it != fdTable_.end()) {
            MemFile& f = it->second;
            if (a1 == 0) f.pos = a2;
            else if (a1 == 1) f.pos += a2;
            else if (a1 == 2) f.pos = (u64)((i64)f.data.size() + (i64)a2);
            r = f.pos;
        }
    } else if (x8 == 80) {  // fstat
        r = 0;
    } else if (x8 == 222) {  // mmap
        u64 addr = a0, length = a1;
        if (addr == 0) addr = HEAP + heapPtr_ + 0x100000;
        heapPtr_ += ((length + 0x1000) & ~0xFFFull) + 0x1000;
        uc_mem_map(uc_, pageAlign(addr), pageUp(length), UC_PROT_ALL);
        r = addr;
    } else if (x8 == 226) {  // mprotect
        int prot = 0;
        if (a2 & 1) prot |= UC_PROT_READ;
        if (a2 & 2) prot |= UC_PROT_WRITE;
        if (a2 & 4) prot |= UC_PROT_EXEC;
        uc_mem_protect(uc_, pageAlign(a0), pageUp(a1), prot);
        if (a0 == opt_.initTrigger) doInit_ = true;
        r = 0;
    } else if (x8 == 172 || x8 == 178) {
        r = 1234;
    } else if (x8 == 160) {  // uname
        r = 0;
    } else if (x8 == 174) {
        r = 10123;
    } else if (x8 == 79) {
        r = 0;
    } else if (x8 == 48) {
        r = 0;
    } else if (x8 == 96) {
        r = 1234;
    } else if (x8 == 98) {  // futex
        r = 0;
    } else if (x8 == 113) {  // clock_gettime
        r = 0;
    } else if (x8 == 318) {  // getrandom
        std::vector<u8> z((size_t)a1, 0);
        if (a1) uc_mem_write(uc_, a0, z.data(), a1);
        r = a1;
    } else if (x8 == 261) {  // prctl
        r = 0;
    } else if (x8 == 129 || x8 == 130 || x8 == 131 || x8 == 117) {
        r = 0;
    } else if (x8 == 61 || x8 == 29) {
        r = 0;
    } else {
        r = 0;
    }

    writeReg(UC_ARM64_REG_X0, r);
    writeReg(UC_ARM64_REG_PC, readReg(UC_ARM64_REG_PC) + 4);

    if (doInit_) {
        doInit_ = false;
        u64 p = FILEBUF + 0x800100;
        const char* dom = "domain";
        uc_mem_write(uc_, p, dom, 7);
        writeReg(UC_ARM64_REG_X0, p);
        writeReg(UC_ARM64_REG_LR, TRAP);
        writeReg(UC_ARM64_REG_PC, opt_.il2cppInit);
        if (verbose_) std::fprintf(stderr, "[emu] call il2cpp_init\n");
    }
}

bool Emulator::isTargetChunksComplete(const Emulator& e) {
    for (u32 s : kTargetSizes)
        if (!e.seenSizes_.count(s)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// driving
// ---------------------------------------------------------------------------
void Emulator::runInitArray() {
    auto init = elf_.parseInitArray();
    if (verbose_) std::fprintf(stderr, "[emu] init_array entries: %zu\n", init.size());
    for (u64 ptr : init) {
        if (!ptr) continue;
        writeReg(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x1000);
        writeReg(UC_ARM64_REG_LR, TRAP);
        writeReg(UC_ARM64_REG_X0, 0);
        uc_err err = uc_emu_start(uc_, ptr, TRAP, 5'000'000, 20'000'000);
        if (verbose_)
            std::fprintf(stderr, "[emu] init_array %s err=%d pc=%s\n", hex(ptr).c_str(), (int)err,
                         hex(readReg(UC_ARM64_REG_PC)).c_str());
        if (stop_) break;
    }
}

void Emulator::mainLoop() {
    u64 entry = elf_.dynGet(12, 0);  // DT_INIT
    if (verbose_) std::fprintf(stderr, "[emu] DT_INIT=%s\n", hex(entry).c_str());
    if (!entry) return;
    writeReg(UC_ARM64_REG_PC, entry);

    t0_ = (double)std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now().time_since_epoch())
              .count() / 1000.0;

    auto now = []() {
        return (double)std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count() / 1000.0;
    };

    u64 pc = entry;
    while (now() - t0_ < opt_.maxSeconds) {
        uc_err err = uc_emu_start(uc_, pc, 0, 30'000'000, 20'000'000);
        pc = readReg(UC_ARM64_REG_PC);
        if (verbose_)
            std::fprintf(stderr, "[emu] progress pc=%s imported=%d elapsed=%.1fs\n", hex(pc).c_str(),
                         (int)importCount_.size(), now() - t0_);
        if (err != UC_ERR_OK && err != UC_ERR_INSN_INVALID) {
            // errors such as unmapped-fetch are handled by hooks (which set stop_)
        }
        if (isTargetChunksComplete(*this)) { if (verbose_) std::fprintf(stderr, "[emu] metadata chunks complete (%.1fs)\n", now() - t0_); break; }
        if (pc == TRAP || stop_) break;
    }
    if (verbose_) std::fprintf(stderr, "[emu] stopped pc=%s\n", hex(pc).c_str());
}

EmuResult Emulator::run() {
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc_);
    if (err != UC_ERR_OK) { std::fprintf(stderr, "[emu] uc_open failed\n"); std::exit(3); }

    mapSegments();
    mapExtra();
    installHandlers();
    applyRelocations();
    installHooks();

    runInitArray();
    mainLoop();

    EmuResult res;
    res.stopped = stop_;
    res.heap.resize(HEAP_SIZE);
    if (uc_mem_read(uc_, HEAP, res.heap.data(), HEAP_SIZE) != UC_ERR_OK)
        std::fprintf(stderr, "[emu] heap read failed\n");
    for (size_t i = 0; i < mapped_.size(); ++i) {
        u64 b = mapped_[i].first, e = mapped_[i].second.first;
        std::vector<u8> seg((size_t)(e - b));
        if (uc_mem_read(uc_, b, seg.data(), e - b) != UC_ERR_OK)
            std::fprintf(stderr, "[emu] seg %zu read failed\n", i);
        res.segments[(int)i] = std::move(seg);
        res.segRange[(int)i] = {b, e};
    }
    res.chunks = chunks_;
    return res;
}

}  // namespace hd