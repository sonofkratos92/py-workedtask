// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 & SHA-256)

#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

static const char* kTag = "[Javelin AntiCheat] ";

enum ExitCode : int {
    kExitOk = 0,
    kExitDebugger = 0xDEB,
    kExitBadProcess = 0xBAD,
    kExitIntegrityFailed = 0xC2C
};

// --- Configurable lists ---
static std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
};

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

// Simple CRC32 (polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

// Compute SHA-256 hex digest using Windows CryptoAPI
static bool sha256Hex(const std::vector<uint8_t>& data, std::string& outHex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }
    if (!data.empty() && !CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    DWORD hashLen = 32;
    uint8_t digest[32]{};
    if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (DWORD i = 0; i < hashLen; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    outHex = oss.str();
    return true;
}

static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(out.data()), size)) return false;
    return true;
}

static bool getRunningExecutableBytes(std::vector<uint8_t>& bytes) {
    std::vector<wchar_t> pathBuf(MAX_PATH);
    DWORD copied = GetModuleFileNameW(nullptr, pathBuf.data(), static_cast<DWORD>(pathBuf.size()));
    while (copied == pathBuf.size() && pathBuf.size() < 32768) {
        pathBuf.resize(pathBuf.size() * 2);
        copied = GetModuleFileNameW(nullptr, pathBuf.data(), static_cast<DWORD>(pathBuf.size()));
    }
    if (copied == 0 || copied >= pathBuf.size()) return false;
    return readFile(std::wstring(pathBuf.data(), copied), bytes);
}

// --- Checks ---
static bool checkDebugger() {
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
#ifdef _M_IX86
    // 32-bit: fs:[30h] -> PEB, offset 2 = BeingDebugged (BYTE)
    __try {
        BYTE* peb = *(BYTE**)_readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64)
    // 64-bit: gs:[60h] -> PEB
    __try {
        BYTE* peb = *(BYTE**)_readgsqword(0x60);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    return false;
}

static bool checkSuspiciousProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::string name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
}

static bool checkSelfIntegrityCrc32(uint32_t expectedCrc) {
    std::vector<uint8_t> bytes;
    if (!getRunningExecutableBytes(bytes)) return false;
    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

static bool checkSelfIntegritySha256(const std::string& expectedHex) {
    std::vector<uint8_t> bytes;
    if (!getRunningExecutableBytes(bytes)) return false;
    std::string actualHex;
    if (!sha256Hex(bytes, actualHex)) return false;
    return toLower(actualHex) == toLower(expectedHex);
}

// --- Entry helpers (embed a baseline CRC32 or SHA-256 at build time) ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time (e.g., /DJAVELIN_EXPECTED_CRC32=0x12345678u)
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 "" // Set at build time (e.g., /DJAVELIN_EXPECTED_SHA256=""<64-hex>"")
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kExitDebugger;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kExitBadProcess;
    }

    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc32(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC32 mismatch). Exiting.\n";
            return kExitIntegrityFailed;
        }
    }

    const std::string expectedSha256 = JAVELIN_EXPECTED_SHA256;
    if (!expectedSha256.empty()) {
        if (!checkSelfIntegritySha256(expectedSha256)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return kExitIntegrityFailed;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return kExitOk;
}
