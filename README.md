# py-workedtask

Minimal Javelin Anti-Cheat guards in C++ (`AntiCheat.cpp`) and Python (`anticheat.py`), featuring:
- Debugger detection
- Suspicious process scanning
- Optional self-integrity verification (CRC32 / SHA-256)

---

## Integrity Verification Setup

### 1. Python (`anticheat.py`)

`anticheat.py` computes the SHA-256 digest of the script file at startup and compares it against the `JAVELIN_EXPECTED_SHA256` environment variable.

- If `JAVELIN_EXPECTED_SHA256` is unset or empty, the check is skipped.
- If `JAVELIN_EXPECTED_SHA256` is set and does not match the file's SHA-256 digest (or is malformed), `anticheat.py` performs a guarded exit with code `0xC2C`.

**Generate and set `JAVELIN_EXPECTED_SHA256`:**

```bash
# Linux / macOS
export JAVELIN_EXPECTED_SHA256=$(sha256sum anticheat.py | awk '{print $1}')
python3 anticheat.py
```

```powershell
# Windows PowerShell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\anticheat.py -Algorithm SHA256).Hash.ToLower()
python .\anticheat.py
```

---

### 2. C++ (`AntiCheat.cpp`)

`AntiCheat.cpp` supports optional build-time integrity constants for the running executable:
- `JAVELIN_EXPECTED_CRC32`: 32-bit unsigned integer (defaults to `0u`, disabled)
- `JAVELIN_EXPECTED_SHA256`: 64-character hex string (defaults to `""`, disabled)

When enabled, a non-matching hash triggers a guarded exit (`0xC2C`).

**Build with MSVC:**

```powershell
# Build with CRC32 constant
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp advapi32.lib

# Or build with SHA-256 constant
cl /EHsc /DJAVELIN_EXPECTED_SHA256="\"<64-char-sha256-hex>\"" AntiCheat.cpp advapi32.lib
```

---

## Running Tests

```bash
python3 -m unittest test_anticheat.py
```
