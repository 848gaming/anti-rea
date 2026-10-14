#pragma once
/**
 * Anti-REA Native C++ Shield (rea_native_shield.hpp)
 * Countermeasures against morluto/rea Ghidra, Hopper, IDA, LLDB & Frida bridges:
 * 1. Compile-time constexpr XOR string encryption (REA_HIDE_STR):
 *    Strings never appear in .rodata / .rdata, blinding rea search & string xrefs.
 * 2. Opaque Indirect Call Dispatcher (REA_INDIRECT_CALL):
 *    Forces Ghidra/Hopper resolve_native_call_targets into "status: unresolved".
 * 3. Linux/Android Anti-Frida & TracerPid scanner.
 */

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <fstream>

namespace antirea {

template <std::size_t N, uint8_t Key>
struct ObfuscatedString {
    std::array<char, N> encrypted{};

    constexpr ObfuscatedString(const char (&str)[N]) {
        for (std::size_t i = 0; i < N; ++i) {
            encrypted[i] = static_cast<char>(str[i] ^ (Key + static_cast<uint8_t>(i * 19)));
        }
    }

    inline std::string decrypt() const {
        std::string out(N - 1, '\0');
        volatile uint8_t runtimeKey = Key;
        for (std::size_t i = 0; i < N - 1; ++i) {
            out[i] = static_cast<char>(encrypted[i] ^ (runtimeKey + static_cast<uint8_t>(i * 19)));
        }
        return out;
    }
};

// Volatile indirect call wrapper that prevents static high-p-code call target resolution in Ghidra
template <typename Func, typename... Args>
__attribute__((noinline)) auto indirectDispatch(Func fn, Args... args) {
    volatile uintptr_t addr = reinterpret_cast<uintptr_t>(fn);
    volatile uintptr_t mask = 0x5A5A5A5A5A5A5A5AULL;
    addr ^= mask;
    addr ^= mask;
    auto resolved = reinterpret_cast<Func>(addr);
    return resolved(args...);
}

inline bool detectFridaOrDebuggerLinux() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            int pid = std::stoi(line.substr(10));
            if (pid != 0) return true;
        }
    }
    std::ifstream maps("/proc/self/maps");
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos || line.find("gum-js") != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // namespace antirea

#define REA_HIDE_STR(s) ([]{ constexpr antirea::ObfuscatedString<sizeof(s), 0xA7> obf(s); return obf.decrypt(); }())
