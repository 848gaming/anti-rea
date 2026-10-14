# Anti-REA v2.0 (`anti-rea`)

**Counter-Reverse-Engineering, Binary Armor & Cryptographic Code-Lock Toolkit** specifically engineered to defeat AI reverse-engineering agents like [`morluto/rea`](https://github.com/morluto/rea), Ghidra/Hopper headless bridges, JADX MCP, Wakaru JS recovery, and Frida instrumentation.

---

## How `morluto/rea` Works — And How `anti-rea` v2.0 Defeats Every Layer

After auditing the `morluto/rea` source tree and documentation, we mapped its exact static parsers, headless bridges, and runtime observation pipelines alongside their structural failure modes:

| Target Platform | How `morluto/rea` Reverse Engineers Your App | `morluto/rea` Parser Blind Spot (From REA Docs) | How `anti-rea` v2.0 Locks & Blinds It |
| :--- | :--- | :--- | :--- |
| **Flutter (`libapp.so`)** | `identify_flutter_build` & `inspect_dart_aot` locate `_kDart*Snapshot*` ELF symbols, scan for `0xf5f5dcdc` magic, read the 32-char hex Dart SDK snapshot hash 20 bytes later, and dump `package:` source URIs from the Isolate string pool. | *"Address resolution examines every overlapping `PT_LOAD` interpretation... conflicting mappings leave affected symbols unresolved."* & *"A payload without exported snapshot symbols is refused."* | `anti-rea armor <libapp.so> --profile flutter [--safe-dlsym]` scrubs `package:*.dart` URIs in-place (preserving exact byte lengths so ELF offsets never shift), scrubs the 32-byte SDK hash, and injects a **conflicting ELF64 `PT_LOAD` overlap** that leaves symbols unresolved in REA while keeping `_kDart*` intact for stock `libflutter.so` `dlsym()`. |
| **Android APK / DEX** | `inspect_android_package` & `inspect_android_method` run `jadx-headless-mcp` (`ReaJadxBridge.java`) to decompile classes, methods, and xrefs. | *"REA rejects an ambiguous method request rather than silently selecting the first match... REA rejects smali fallback for an overloaded method."* | `ReaAndroidShield.kt` uses **Overload Ambiguity Traps** (giving sensitive methods identical names with decoy overload signatures so REA refuses both Java and Smali fallback) + **AES-256-GCM `InMemoryDexClassLoader`** + JNI C++ Anti-Frida. |
| **.NET Managed (`.dll`/`.exe`)** | `inspect_managed_artifact` & `inspect_managed_members` parse ECMA-335 `BSJB` metadata headers, CIL bodies, and `#US` (`0x70` `ldstr`) user strings without executing code. | *"It does not unpack .NET single-file hosts... Inputs without admitted CLI metadata do not become managed assemblies through naming or routing guesses."* | `anti-rea lock` + `ReaDotnetShield.cs` encrypts the `.dll` into a `.realock` AES-256-GCM envelope loaded in RAM via `Assembly.Load(byte[])` and encrypts `#US` strings. |
| **JavaScript / Electron / Web** | `analyze_javascript_application` & Wakaru (`recover_javascript_sources`) parse UTF-8 ASTs to extract literal `ipcMain.handle`, `contextBridge`, tRPC procedure chains (`root.invoice.list.useQuery`), and GraphQL queries. | *"without parsing or executing native `.node` add-ons... Factory bindings must have one unconditional initializer; shadowed locals do not inherit client identity."* | `anti-rea armor --profile js --mangle` + `--profile js-bytecode` strips source maps, flattens control flow with opaque predicates, mangles identifiers (`_0x...`), rewrites IPC/tRPC/GraphQL AST nodes into dynamic computed lookups, and compiles JS into **V8 binary cached bytecode (`.jsc`)** with **0 UTF-8 source text**. |
| **Runtime Hooking / Patching** (`Frida` / `LLDB`) | Attacker patches out anti-debug checks in the loader or hooks runtime functions via `rea instrument-with-frida`. | Static patching alters function source text; monkey-patching alters V8 `[native code]` intrinsic signatures. | **Cryptographic Tamper-Bound Key Derivation**: `anti-rea lock` mixes `SHA-256(__verifyCleanRuntime.toString())` directly into `crypto.hkdfSync` key derivation. Editing even 1 character of the anti-debug/anti-Frida guard produces a wrong AES-256-GCM key and mathematically fails decryption! |
| **Electron Runtime (`--inspect`)** | `inspect_electron_fuses` checks `EnableNodeCliInspectArguments` before attaching `observe_javascript_runtime` via CDP. | *"When `EnableNodeCliInspectArguments` is disabled, Electron ignores Inspector flags."* | `anti-rea armor <binary> --profile electron-fuses` patches the binary's `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX` fuse wire to disable `--inspect` and `ELECTRON_RUN_AS_NODE`. |
| **Native Binaries (C/C++/Rust)** | `ReaGhidraBridge.java` & `hopper_bridge.py` search cleartext strings, symbols, and static call targets (`resolve_native_call_targets`). | Indirect calls via computed registers return `status: "unresolved"` in `resolve_native_call_targets`. | `rea_native_shield.hpp` provides `constexpr` compile-time XOR string encryption (`REA_HIDE_STR`) so strings never enter `.rodata`, plus volatile indirect call dispatchers (`antirea::indirectDispatch`) and Linux `/proc/self/maps` + `TracerPid` Anti-Frida checks. |

---

## Quick Start

### 1. Audit Any File or App (Red-Team Scanner)
See the exact Exposure Score (0–100) and static artifacts that `morluto/rea` would extract from your binary or bundle:

```bash
node ./bin/anti-rea.mjs audit <path-to-file-or-dir>
```

### 2. Armor Your Code or Binary Against REA Static Parsers
```bash
# JavaScript / Electron / Web bundle AST blinding, control-flow flattening & identifier mangling
node ./bin/anti-rea.mjs armor ./app.js --profile js --mangle --out ./app.armored.js

# Compile JS directly into V8 binary cached bytecode (.jsc) with ZERO UTF-8 source text
node ./bin/anti-rea.mjs armor ./app.js --profile js-bytecode --out ./app.jsc

# Flip Electron binary security fuses (disables --inspect and ELECTRON_RUN_AS_NODE)
node ./bin/anti-rea.mjs armor ./MyElectronApp.exe --profile electron-fuses --out ./MyElectronApp.hardened.exe

# Scrub Flutter libapp.so package: URIs, SDK hash & inject ELF64 PT_LOAD conflict (safe for stock libflutter.so dlsym)
node ./bin/anti-rea.mjs armor ./libapp.so --profile flutter --safe-dlsym --out ./libapp.armored.so

# Mask .NET PE/CLI BSJB metadata header for encrypted host loading
node ./bin/anti-rea.mjs armor ./CoreLogic.dll --profile dotnet --out ./CoreLogic.armored.dll
```

### 3. Cryptographic Code-Lock v2.0 (`.realock` AES-256-GCM + Tamper-Bound HKDF + V8 Bytecode)
Lock any JS bundle, `.asar`, `.dex`, or `.dll` into an authenticated `.realock` container. With `--bytecode`, JS is first compiled to eager V8 binary bytecode (`.jsc`) before AES-256-GCM encryption, and the HKDF decryption key is cryptographically bound to the SHA-256 digest of the runtime anti-debug/anti-Frida guard:

```bash
node ./bin/anti-rea.mjs lock ./app.armored.js --bytecode --secret "your-master-key"
```

### 4. Generate Drop-In Multi-Platform Runtime Shields
Emit ready-to-use protection SDK files for Android (Kotlin), Native (C++), Flutter (Dart FFI), and .NET (C#):

```bash
node ./bin/anti-rea.mjs init-sdk ./sdk
```

### 5. Run Verification Tests (8 Suites) & Live Demo
```bash
npm test
npm run demo
```
