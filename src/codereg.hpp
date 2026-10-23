#pragma once
#include "bytes.hpp"
#include "elf.hpp"
#include "emulator.hpp"
#include "metadata.hpp"

namespace hd {

// Deterministically locate the real Il2CppCodeGenModule for every metadata image
// by matching the image name against the module name pointer inside the runtime
// library segments. Returns module VAs in metadata image order (empty on failure).
std::vector<u64> findModules(const EmuResult& res, const Metadata& meta);

// Build the runtime ELF (overlay decrypted segments + synthetic CodeRegistration
// PT_LOAD + real module table + symbols + Il2CppType fix). Writes into `outElf`.
bool buildRuntimeElf(const ElfFile& orig, const EmuResult& res, const Metadata& meta,
                     const std::vector<u64>& modules, std::vector<u8>& outElf);

// Build real_method_pointers.tsv text from metadata + module method-pointer arrays.
std::string buildMethodMap(const ElfFile& orig, const EmuResult& res, const Metadata& meta,
                           const std::vector<u64>& modules);

}  // namespace hd