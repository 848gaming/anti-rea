import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Official Electron Fuse V1 Sentinel (32 bytes ASCII)
 * Used by morluto/rea `inspect_electron_fuses` to read the fuse wire in Electron binaries.
 */
export const ELECTRON_FUSE_SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'utf8');

/**
 * Dart AOT Snapshot Magic (`0xf5f5dcdc`)
 * Used by morluto/rea `identify_flutter_build` and `inspect_dart_aot`.
 */
export const DART_SNAPSHOT_MAGIC_LE = Buffer.from([0xdc, 0xdc, 0xf5, 0xf5]);
export const DART_SNAPSHOT_MAGIC_BE = Buffer.from([0xf5, 0xf5, 0xdc, 0xdc]);

/**
 * .NET CLI Metadata Root Signature (`BSJB` = 0x424A5342)
 * Used by morluto/rea `inspect_managed_artifact` and `inspect_managed_members`.
 */
export const DOTNET_BSJB_MAGIC = Buffer.from('BSJB', 'utf8');

/**
 * REALOCK Encrypted Container Magic (`RLCK\x01`)
 */
export const REALOCK_MAGIC = Buffer.from('RLCK\x01', 'utf8');

/**
 * Audits a target file using the exact static recognition rules that morluto/rea uses.
 * Returns a structured vulnerability & exposure report showing what REA can extract.
 */
export function auditTargetForRea(filePath) {
  const resolvedPath = path.resolve(filePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Target file not found: ${resolvedPath}`);
  }

  const stat = fs.statSync(resolvedPath);
  if (stat.isDirectory()) {
    return auditDirectoryForRea(resolvedPath);
  }

  const buf = fs.readFileSync(resolvedPath);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const ext = path.extname(resolvedPath).toLowerCase();

  // Check if already protected by REALOCK
  if (buf.subarray(0, REALOCK_MAGIC.length).equals(REALOCK_MAGIC)) {
    return {
      target: resolvedPath,
      sha256,
      size: buf.length,
      detectedType: 'realock-encrypted-container',
      reaExposureScore: 0,
      riskLevel: 'PROTECTED (LOCKED)',
      findings: [
        {
          surface: 'Cryptographic Code-Lock',
          severity: 'NONE',
          detail: 'Payload is encrypted with AES-256-GCM + HKDF-SHA256 (.realock). REA static parsers, AST extractors, Ghidra, and JADX see only high-entropy ciphertext.'
        }
      ],
      recommendations: []
    };
  }

  // Check if compiled to V8 Cached Bytecode (RJSC)
  if (buf.length >= 12 && buf.subarray(0, 4).toString('utf8') === 'RJSC') {
    return {
      target: resolvedPath,
      sha256,
      size: buf.length,
      detectedType: 'v8-bytecode-bundle',
      reaExposureScore: 0,
      riskLevel: 'PROTECTED (V8 BYTECODE)',
      findings: [
        {
          surface: 'V8 Binary Cached Bytecode (.jsc)',
          severity: 'NONE',
          detail: 'Contains zero UTF-8 JavaScript source text. REA AST parsers and Wakaru cannot decompile V8 binary cachedData.'
        }
      ],
      recommendations: []
    };
  }

  const findings = [];
  const recommendations = [];
  let exposurePoints = 0;
  let detectedType = detectArtifactType(buf, ext, resolvedPath);

  // 1. Check Electron Fuse Wire (if present)
  const fuseAudit = inspectElectronFusesInBuffer(buf);
  if (fuseAudit.present) {
    detectedType = 'electron-binary';
    if (fuseAudit.fuses.EnableNodeCliInspectArguments !== 'DISABLED') {
      exposurePoints += 30;
      findings.push({
        surface: 'Electron Fuse: EnableNodeCliInspectArguments',
        severity: 'CRITICAL',
        detail: `Fuse is ${fuseAudit.fuses.EnableNodeCliInspectArguments}. REA's observe_javascript_runtime / list_electron_targets can attach via --inspect / CDP.`
      });
      recommendations.push('Run `anti-rea armor <binary> --profile electron-fuses` to flip EnableNodeCliInspectArguments to 0.');
    }
    if (fuseAudit.fuses.RunAsNode !== 'DISABLED') {
      exposurePoints += 20;
      findings.push({
        surface: 'Electron Fuse: RunAsNode',
        severity: 'HIGH',
        detail: `Fuse is ${fuseAudit.fuses.RunAsNode}. Attackers can use ELECTRON_RUN_AS_NODE=1 to execute arbitrary scripts with your app binary's entitlements.`
      });
    }
    if (fuseAudit.fuses.EnableEmbeddedAsarIntegrityValidation !== 'ENABLED') {
      exposurePoints += 15;
      findings.push({
        surface: 'Electron Fuse: EnableEmbeddedAsarIntegrityValidation',
        severity: 'MEDIUM',
        detail: 'ASAR integrity validation is not enforced at the binary fuse level.'
      });
    }
    if (fuseAudit.fuses.OnlyLoadAppFromAsar !== 'ENABLED') {
      exposurePoints += 15;
      findings.push({
        surface: 'Electron Fuse: OnlyLoadAppFromAsar',
        severity: 'MEDIUM',
        detail: 'App allows loading unpacked code outside app.asar.'
      });
    }
  }

  // 2. Check Flutter / Dart AOT Snapshot (`libapp.so`)
  const flutterAudit = inspectFlutterAotInBuffer(buf);
  if (flutterAudit.detected) {
    detectedType = 'flutter-aot-library';
    if (flutterAudit.exportedSymbols.length > 0) {
      exposurePoints += 35;
      findings.push({
        surface: 'Flutter AOT Symbols (_kDart*Snapshot*)',
        severity: 'CRITICAL',
        detail: `Found ${flutterAudit.exportedSymbols.length} exported Dart snapshot symbols (${flutterAudit.exportedSymbols.join(', ')}). REA's inspect_dart_aot uses these to locate the Isolate snapshot.`
      });
    }
    if (flutterAudit.snapshotHashes.length > 0) {
      exposurePoints += 25;
      findings.push({
        surface: 'Flutter Snapshot Magic & SDK Build Hash',
        severity: 'HIGH',
        detail: `Found Dart snapshot magic (0xf5f5dcdc) with SDK snapshot hash(es): ${flutterAudit.snapshotHashes.join(', ')}. REA's identify_flutter_build maps this hash to the exact Dart SDK layout.`
      });
    }
    if (flutterAudit.packageUris.length > 0) {
      exposurePoints += 40;
      findings.push({
        surface: 'Flutter Isolate String Pool (package: URIs)',
        severity: 'CRITICAL',
        detail: `Exposed ${flutterAudit.packageUris.length} Dart source package: URIs (e.g. ${flutterAudit.packageUris.slice(0, 4).join(', ')}). REA extracts your entire internal module & dependency structure.`
      });
      recommendations.push('Run `anti-rea armor <libapp.so> --profile flutter` to scrub package: URIs, mask snapshot magic headers, and strip _kDart*Snapshot* symbol strings.');
    }
  }

  // 3. Check .NET Managed PE/CLI Metadata (`BSJB`)
  const dotnetAudit = inspectDotnetInBuffer(buf);
  if (dotnetAudit.detected) {
    detectedType = 'dotnet-managed-assembly';
    exposurePoints += 40;
    findings.push({
      surface: '.NET ECMA-335 CLI Metadata Root (BSJB)',
      severity: 'CRITICAL',
      detail: `Found intact BSJB CLI metadata root at offset 0x${dotnetAudit.bsjbOffset.toString(16)} (Runtime version: ${dotnetAudit.versionString}) with streams: ${dotnetAudit.streams.join(', ')}. REA's inspect_managed_members can decode all types, methods, and #US user strings.`
    });
    if (dotnetAudit.exposedIdentifiers.length > 0) {
      exposurePoints += 30;
      findings.push({
        surface: '.NET #Strings / #US Literal Exposure',
        severity: 'HIGH',
        detail: `Exposed ${dotnetAudit.exposedIdentifiers.length} readable identifiers/strings (sample: ${dotnetAudit.exposedIdentifiers.slice(0, 5).join(', ')}).`
      });
    }
    recommendations.push('Run `anti-rea armor <assembly.dll> --profile dotnet` or `anti-rea lock` to pack the assembly into an encrypted Native Host and obfuscate CLI metadata headers.');
  }

  // 4. Check JavaScript / TypeScript / Electron AST & Bundle Surface
  if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.asar'].includes(ext) || detectedType === 'javascript-source') {
    const jsAudit = inspectJavaScriptSurface(buf.toString('utf8'));
    if (jsAudit.totalExposures > 0) {
      if (jsAudit.ipcChannels.length > 0) {
        exposurePoints += 25;
        findings.push({
          surface: 'Electron Static IPC Channels',
          severity: 'HIGH',
          detail: `REA analyze_javascript_application can statically extract ${jsAudit.ipcChannels.length} literal IPC channels: ${jsAudit.ipcChannels.slice(0, 5).join(', ')}`
        });
      }
      if (jsAudit.contextBridgeKeys.length > 0) {
        exposurePoints += 20;
        findings.push({
          surface: 'Electron contextBridge API Keys',
          severity: 'HIGH',
          detail: `REA extracts preload bridge keys: ${jsAudit.contextBridgeKeys.join(', ')}`
        });
      }
      if (jsAudit.trpcProcedures.length > 0) {
        exposurePoints += 25;
        findings.push({
          surface: 'tRPC Static Procedure Chains',
          severity: 'HIGH',
          detail: `REA's trpc:procedure recognizer matched ${jsAudit.trpcProcedures.length} API procedure paths: ${jsAudit.trpcProcedures.slice(0, 5).join(', ')}`
        });
      }
      if (jsAudit.graphqlOps.length > 0) {
        exposurePoints += 20;
        findings.push({
          surface: 'GraphQL Named Operations',
          severity: 'MEDIUM',
          detail: `REA's graphql:* recognizer matched operations: ${jsAudit.graphqlOps.slice(0, 5).join(', ')}`
        });
      }
      if (jsAudit.sourceMaps.length > 0) {
        exposurePoints += 30;
        findings.push({
          surface: 'SourceMap Declarations',
          severity: 'CRITICAL',
          detail: `Found ${jsAudit.sourceMaps.length} sourceMappingURL directives allowing full original source reconstruction.`
        });
      }
      if (jsAudit.stringLiteralsCount > 3) {
        exposurePoints += 20;
        findings.push({
          surface: 'Cleartext String & URL Literals',
          severity: 'MEDIUM',
          detail: `Found ${jsAudit.stringLiteralsCount} sensitive/endpoint string literals readable by Wakaru & REA AST projection.`
        });
      }
      recommendations.push('Run `anti-rea armor <file.js> --profile js` to blind REA AST recognizers (shadowing tRPC factories, dynamic HMAC IPC channels, polymorphic string vault, anti-inspector guard).');
      recommendations.push('Run `anti-rea lock <file.js>` to encrypt the bundle into an AES-256-GCM .realock container.');
    }
  }

  // 5. Generic Native / Binary Cleartext String & Debug Check
  if (detectedType === 'native-binary' || detectedType === 'android-dex-or-apk') {
    const asciiStrings = extractReadableStrings(buf, 8);
    const sensitiveStrings = asciiStrings.filter((s) =>
      /^(https?:\/\/|wss?:\/\/|\/api\/|\/v1\/|Bearer |SECRET|PRIVATE|API_KEY|Lcom\/[a-z0-9_]+\/)/i.test(s)
    );
    if (sensitiveStrings.length > 0) {
      exposurePoints += 35;
      findings.push({
        surface: 'Binary Cleartext String Table',
        severity: 'HIGH',
        detail: `Found ${sensitiveStrings.length} high-value strings/descriptors (sample: ${sensitiveStrings.slice(0, 4).join(', ')}) exposed to REA's Ghidra/Hopper/JADX string search.`
      });
      recommendations.push('Use `anti-rea armor <file> --profile native` (or `--profile android`) to encrypt string literals and generate indirect-call/overload traps.');
    }
  }

  const reaExposureScore = Math.min(100, exposurePoints);
  const riskLevel =
    reaExposureScore >= 70
      ? 'CRITICAL (FULLY EXPOSED TO REA)'
      : reaExposureScore >= 35
      ? 'HIGH (PARTIALLY EXPOSED TO REA)'
      : reaExposureScore > 0
      ? 'LOW (MINIMAL STATIC SURFACE)'
      : 'PROTECTED (BLINDED TO REA)';

  return {
    target: resolvedPath,
    sha256,
    size: buf.length,
    detectedType,
    reaExposureScore,
    riskLevel,
    fuseAudit: fuseAudit.present ? fuseAudit : undefined,
    flutterAudit: flutterAudit.detected ? flutterAudit : undefined,
    dotnetAudit: dotnetAudit.detected ? dotnetAudit : undefined,
    findings,
    recommendations
  };
}

function auditDirectoryForRea(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const results = [];
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dirPath, entry.name);
    if (entry.isFile()) {
      results.push(auditTargetForRea(full));
    }
  }
  const avgScore =
    results.length > 0
      ? Math.round(results.reduce((acc, r) => acc + r.reaExposureScore, 0) / results.length)
      : 0;
  return {
    target: dirPath,
    detectedType: 'directory',
    filesAudited: results.length,
    reaExposureScore: avgScore,
    results
  };
}

function detectArtifactType(buf, ext, filePath) {
  if (buf.subarray(0, REALOCK_MAGIC.length).equals(REALOCK_MAGIC)) return 'realock-encrypted-container';
  if (buf.includes(ELECTRON_FUSE_SENTINEL)) return 'electron-binary';
  if (buf.includes(DART_SNAPSHOT_MAGIC_LE) || buf.includes(DART_SNAPSHOT_MAGIC_BE) || buf.includes(Buffer.from('_kDartIsolateSnapshotData'))) {
    return 'flutter-aot-library';
  }
  if (buf.includes(DOTNET_BSJB_MAGIC)) return 'dotnet-managed-assembly';
  if (buf.subarray(0, 4).equals(Buffer.from('dex\n')) || ext === '.apk' || ext === '.dex') return 'android-dex-or-apk';
  if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'].includes(ext)) return 'javascript-source';
  if (buf.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) || buf.subarray(0, 2).equals(Buffer.from('MZ'))) {
    return 'native-binary';
  }
  return 'generic-artifact';
}

/**
 * Mirrors morluto/rea `inspect_electron_fuses`:
 * Locates `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`, reads wire version & length, and decodes fuse bytes.
 * In Electron Fuse V1 wire format:
 *   offset + 32: fuse_version (uint8, usually 1)
 *   offset + 33: fuse_wire_length (uint8)
 *   offset + 34..: ASCII '0' (0x30 = disabled), '1' (0x31 = enabled), 'r' (0x72 = removed)
 */
export function inspectElectronFusesInBuffer(buf) {
  const idx = buf.indexOf(ELECTRON_FUSE_SENTINEL);
  if (idx === -1 || idx + 34 >= buf.length) {
    return { present: false };
  }
  const version = buf[idx + 32];
  const wireLength = buf[idx + 33];
  const wireStart = idx + 34;
  const fuseNames = [
    'RunAsNode',
    'EnableCookieEncryption',
    'EnableNodeOptionsEnvironmentVariable',
    'EnableNodeCliInspectArguments',
    'EnableEmbeddedAsarIntegrityValidation',
    'OnlyLoadAppFromAsar',
    'LoadBrowserProcessSpecificV8Snapshot',
    'GrantFileProtocolExtraPrivileges'
  ];
  const fuses = {};
  for (let i = 0; i < Math.min(wireLength, fuseNames.length); i++) {
    const byte = buf[wireStart + i];
    fuses[fuseNames[i]] =
      byte === 0x31 ? 'ENABLED' : byte === 0x30 ? 'DISABLED' : byte === 0x72 ? 'REMOVED' : `RAW(0x${byte.toString(16)})`;
  }
  return {
    present: true,
    sentinelOffset: idx,
    version,
    wireLength,
    fuses
  };
}

/**
 * Mirrors morluto/rea `identify_flutter_build` and `inspect_dart_aot`:
 * Checks for `_kDart*Snapshot*` symbols, `f5 f5 dc dc` magic, 32-char hex snapshot hash 20 bytes after magic,
 * and `package:` / `dart:` URIs in the string pool.
 */
export function inspectFlutterAotInBuffer(buf) {
  const symbolNames = [
    '_kDartVmSnapshotData',
    '_kDartVmSnapshotInstructions',
    '_kDartIsolateSnapshotData',
    '_kDartIsolateSnapshotInstructions'
  ];
  const ptLoadConflictProtected = checkElf64PtLoadConflictInAudit(buf);
  const rawSymbols = symbolNames.filter((sym) => buf.includes(Buffer.from(sym, 'utf8')));
  // Per morluto/rea docs/flutter-analysis.md: conflicting overlapping PT_LOAD mappings leave symbols unresolved
  const exportedSymbols = ptLoadConflictProtected ? [] : rawSymbols;

  const snapshotHashes = [];
  for (const magic of [DART_SNAPSHOT_MAGIC_LE, DART_SNAPSHOT_MAGIC_BE]) {
    let pos = 0;
    while ((pos = buf.indexOf(magic, pos)) !== -1) {
      // Snapshot hash in Dart VM header sits 20 bytes after the 4-byte magic (32 ASCII hex chars)
      const hashStart = pos + 20;
      if (hashStart + 32 <= buf.length) {
        const candidate = buf.subarray(hashStart, hashStart + 32).toString('utf8');
        if (/^[0-9a-f]{32}$/i.test(candidate)) {
          snapshotHashes.push(candidate);
        }
      }
      pos += 4;
    }
  }

  const text = buf.toString('latin1');
  const packageUriMatches = text.match(/package:[a-zA-Z0-9_.\-/]+\.dart/g) || [];
  const dartUriMatches = text.match(/dart:[a-zA-Z0-9_.\-/]+/g) || [];
  const packageUris = [...new Set(packageUriMatches)];
  const dartUris = [...new Set(dartUriMatches)];

  const detected = exportedSymbols.length > 0 || snapshotHashes.length > 0 || packageUris.length > 0;
  return {
    detected,
    ptLoadConflictProtected,
    exportedSymbols,
    snapshotHashes: [...new Set(snapshotHashes)],
    packageUris,
    dartUris
  };
}

function checkElf64PtLoadConflictInAudit(buf) {
  if (
    buf.length < 64 ||
    buf[0] !== 0x7f ||
    buf[1] !== 0x45 ||
    buf[2] !== 0x4c ||
    buf[3] !== 0x46 ||
    buf[4] !== 0x02 ||
    buf[5] !== 0x01
  ) {
    return false;
  }
  const phoff = Number(buf.readBigUInt64LE(32));
  const phentsize = buf.readUInt16LE(54);
  const phnum = buf.readUInt16LE(56);
  if (phoff === 0 || phentsize !== 56 || phnum < 2 || phoff + phnum * phentsize > buf.length) {
    return false;
  }
  const loads = [];
  for (let i = 0; i < phnum; i++) {
    const entryOff = phoff + i * phentsize;
    if (buf.readUInt32LE(entryOff) === 1) {
      loads.push({
        offset: buf.readBigUInt64LE(entryOff + 8),
        vaddr: buf.readBigUInt64LE(entryOff + 16),
        memsz: buf.readBigUInt64LE(entryOff + 40)
      });
    }
  }
  for (let i = 0; i < loads.length; i++) {
    for (let j = i + 1; j < loads.length; j++) {
      const a = loads[i];
      const b = loads[j];
      if (a.vaddr < b.vaddr + b.memsz && b.vaddr < a.vaddr + a.memsz && a.offset !== b.offset) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Mirrors morluto/rea `inspect_managed_artifact` and `inspect_managed_members`:
 * Scans for ECMA-335 CLI metadata root `BSJB` and stream headers (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`).
 */
export function inspectDotnetInBuffer(buf) {
  const bsjbOffset = buf.indexOf(DOTNET_BSJB_MAGIC);
  if (bsjbOffset === -1 || bsjbOffset + 16 >= buf.length) {
    return { detected: false };
  }
  const versionLen = buf.readUInt32LE(bsjbOffset + 12);
  let versionString = 'unknown';
  if (versionLen > 0 && versionLen < 64 && bsjbOffset + 16 + versionLen <= buf.length) {
    versionString = buf.subarray(bsjbOffset + 16, bsjbOffset + 16 + versionLen).toString('utf8').replace(/\0+$/, '');
  }
  const streamCandidates = ['#~', '#Strings', '#US', '#GUID', '#Blob'];
  const streams = streamCandidates.filter((s) => buf.indexOf(Buffer.from(s, 'utf8'), bsjbOffset) !== -1);

  const asciiStrings = extractReadableStrings(buf, 6);
  const exposedIdentifiers = asciiStrings.filter(
    (s) => !streamCandidates.includes(s) && !s.startsWith('BSJB') && /^[A-Za-z0-9_.]+$/.test(s)
  );

  return {
    detected: true,
    bsjbOffset,
    versionString,
    streams,
    exposedIdentifiers
  };
}

/**
 * Mirrors morluto/rea `analyze_javascript_application`:
 * Detects static IPC channels, contextBridge keys, tRPC procedure chains, GraphQL queries, and source maps.
 */
export function inspectJavaScriptSurface(source) {
  const ipcChannels = [];
  const ipcRegex = /\b(?:ipcMain|ipcRenderer)\s*\.\s*(?:handle|on|once|invoke|send|sendSync)\s*\(\s*(['"`])([^'"`]+)\1/g;
  let m;
  while ((m = ipcRegex.exec(source)) !== null) {
    ipcChannels.push(m[2]);
  }

  const contextBridgeKeys = [];
  const cbRegex = /\bcontextBridge\s*\.\s*exposeIn(?:Main|Isolated)World\s*\(\s*(['"`])([^'"`]+)\1/g;
  while ((m = cbRegex.exec(source)) !== null) {
    contextBridgeKeys.push(m[2]);
  }

  const trpcProcedures = [];
  const trpcRegex = /\b([a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)+)\s*\.\s*(useQuery|useMutation|useInfiniteQuery|useSubscription|query|mutate)\s*\(/g;
  while ((m = trpcRegex.exec(source)) !== null) {
    trpcProcedures.push(`${m[1]}.${m[2]}`);
  }

  const graphqlOps = [];
  const gqlRegex = /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|@|\{)/g;
  while ((m = gqlRegex.exec(source)) !== null) {
    graphqlOps.push(`${m[1]} ${m[2]}`);
  }

  const sourceMaps = [];
  const smRegex = /\/\/[#@]\s*sourceMappingURL=(.+)/g;
  while ((m = smRegex.exec(source)) !== null) {
    sourceMaps.push(m[1].trim());
  }

  const sensitiveLiterals = [];
  const strRegex = /(['"`])((?:https?:\/\/|\/api\/|\/trpc|Bearer |sk_|pk_|AIza)[^'"`\n]{3,})\1/g;
  while ((m = strRegex.exec(source)) !== null) {
    sensitiveLiterals.push(m[2]);
  }

  const totalExposures =
    ipcChannels.length +
    contextBridgeKeys.length +
    trpcProcedures.length +
    graphqlOps.length +
    sourceMaps.length +
    sensitiveLiterals.length;

  return {
    totalExposures,
    ipcChannels: [...new Set(ipcChannels)],
    contextBridgeKeys: [...new Set(contextBridgeKeys)],
    trpcProcedures: [...new Set(trpcProcedures)],
    graphqlOps: [...new Set(graphqlOps)],
    sourceMaps,
    stringLiteralsCount: sensitiveLiterals.length,
    sensitiveLiterals: [...new Set(sensitiveLiterals)]
  };
}

function extractReadableStrings(buf, minLen = 6) {
  const result = [];
  let current = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) {
        result.push(current);
      }
      current = '';
    }
  }
  if (current.length >= minLen) {
    result.push(current);
  }
  return result;
}
