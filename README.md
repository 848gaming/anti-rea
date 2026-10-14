# Anti-REA (`anti-rea`)

**Counter-Reverse-Engineering, Binary Armor & Cryptographic Code-Lock Toolkit** specifically engineered to defeat AI reverse-engineering agents like [`morluto/rea`](https://github.com/morluto/rea), Ghidra/Hopper headless bridges, JADX MCP, Wakaru JS recovery, and Frida instrumentation.

---

## How `morluto/rea` Works — And How `anti-rea` Defeats Every Layer

After auditing the `morluto/rea` source tree and documentation, we mapped its exact static parsers, headless bridges, and runtime observation pipelines alongside their structural failure modes:

| Target Platform | How `morluto/rea` Reverse Engineers Your App | `morluto/rea` Parser Blind Spot (From REA Docs) | How `anti-rea` Locks & Blinds It |
| :--- | :--- | :--- | :--- |
| **Flutter (`libapp.so`)** | `identify_flutter_build` & `inspect_dart_aot` locate `_kDart*Snapshot*` ELF symbols, scan for `0xf5f5dcdc` magic, read the 32-char hex Dart SDK snapshot hash 20 bytes later, and dump `package:` source URIs from the Isolate string pool. | *"A payload without exported snapshot symbols is refused rather than guessed at."* | `anti-rea armor <libapp.so> --profile flutter` scrubs `package:*.dart` URIs in-place (preserving exact byte lengths so ELF offsets never shift), anonymizes the 32-byte SDK hash, and masks `_kDart*Snapshot*` symbols. |
| **Android APK / DEX** | `inspect_android_package` & `inspect_android_method` run `jadx-headless-mcp` (`ReaJadxBridge.java`) to decompile classes, methods, and xrefs. | *"REA rejects an ambiguous method request rather than silently selecting the first match... REA rejects smali fallback for an overloaded method."* | `ReaAndroidShield.kt` uses **Overload Ambiguity Traps** (giving sensitive methods identical names with decoy overload signatures so REA refuses both Java and Smali fallback) + **AES-256-GCM `InMemoryDexClassLoader`** + JNI C++ Anti-Frida. |
| **.NET Managed (`.dll`/`.exe`)** | `inspect_managed_artifact` & `inspect_managed_members` parse ECMA-335 `BSJB` metadata headers, CIL bodies, and `#US` (`0x70` `ldstr`) user strings without executing code. | *"It does not unpack .NET single-file hosts... Inputs without admitted CLI metadata do not become managed assemblies through naming or routing guesses."* | `anti-rea lock` + `ReaDotnetShield.cs` encrypts the `.dll` into a `.realock` AES-256-GCM envelope loaded in RAM via `Assembly.Load(byte[])` and encrypts `#US` strings. |
| **JavaScript / Electron / Web** | `analyze_javascript_application` & Wakaru (`recover_javascript_sources`) parse UTF-8 ASTs to extract literal `ipcMain.handle`, `contextBridge`, tRPC procedure chains (`root.invoice.list.useQuery`), and GraphQL queries. | *"without parsing or executing native `.node` add-ons... Factory bindings must have one unconditional initializer; shadowed locals do not inherit client identity."* | `anti-rea armor --profile js` strips source maps, moves strings into a rolling-XOR vault, and rewrites IPC, `contextBridge`, tRPC, and GraphQL AST nodes into dynamic computed bracket dispatches (`obj[__reaV(i)]`) + `.realock` encryption. |
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
# JavaScript / Electron / Web bundle AST blinding & string vault
node ./bin/anti-rea.mjs armor ./app.js --profile js --out ./app.armored.js

# Flip Electron binary security fuses (disables --inspect and ELECTRON_RUN_AS_NODE)
node ./bin/anti-rea.mjs armor ./MyElectronApp.exe --profile electron-fuses --out ./MyElectronApp.hardened.exe

# Scrub Flutter libapp.so package: URIs, Dart SDK snapshot hash & snapshot symbols
node ./bin/anti-rea.mjs armor ./libapp.so --profile flutter --out ./libapp.armored.so

# Mask .NET PE/CLI BSJB metadata header for encrypted host loading
node ./bin/anti-rea.mjs armor ./CoreLogic.dll --profile dotnet --out ./CoreLogic.armored.dll
```

### 3. Cryptographic Code-Lock (`.realock` AES-256-GCM + HKDF-SHA256)
Lock any JS bundle, `.asar`, `.dex`, or `.dll` into an authenticated `.realock` container with a self-defending runtime unlocker that checks for debuggers, Node Inspector, and Frida before deriving the decryption key in memory:

```bash
node ./bin/anti-rea.mjs lock ./app.armored.js --secret "your-master-key"
```

### 4. Generate Drop-In Multi-Platform Runtime Shields
Emit ready-to-use protection SDK files for Android (Kotlin), Native (C++), Flutter (Dart FFI), and .NET (C#):

```bash
node ./bin/anti-rea.mjs init-sdk ./sdk
```

### 5. Run Verification Tests & Live Demo
```bash
npm test
npm run demo
```
