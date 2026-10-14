#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {
  auditTargetForRea,
  lockFile,
  decryptRealockBuffer,
  armorJavaScriptSource,
  armorElectronFusesInBuffer,
  armorFlutterBinaryInBuffer,
  armorDotnetBinaryInBuffer,
  generatePlatformShieldSdk
} from '../src/index.mjs';

function printHelp() {
  console.log(`
================================================================================
  ANTI-REA: Counter-Reverse-Engineering, Binary Armor & Code-Lock Toolkit
  Engineered to blind & lock apps against AI reverse-engineering (morluto/rea)
================================================================================

Usage:
  anti-rea audit <path> [--json]
      Scans a binary, APK, Flutter libapp.so, .NET assembly, Electron app, or JS bundle
      using REA's exact static recognition patterns and reports an Exposure Score.

  anti-rea lock <input-path> [--out <vault.realock>] [--secret <passphrase>]
      Encrypts any code/binary payload into an authenticated AES-256-GCM + HKDF-SHA256
      .realock container and generates a self-defending runtime loader (.locked.mjs).

  anti-rea unlock <vault.realock> --secret <passphrase> [--out <output-path>]
      Verifies and decrypts a .realock container.

  anti-rea armor <input-path> --profile <js|electron-fuses|flutter|dotnet> [--out <output-path>]
      Applies targeted binary/AST armor to blind morluto/rea's static parsers:
        - js             : Encrypts string literals, blinds IPC/contextBridge/tRPC/GraphQL AST
        - electron-fuses : Flips Electron Fuse wire (disables --inspect & RunAsNode)
        - flutter        : Scrubs package: URIs in libapp.so, masks snapshot hash & symbols
        - dotnet         : Masks ECMA-335 BSJB CLI root header for encrypted host loading

  anti-rea init-sdk <output-directory>
      Generates drop-in Multi-Platform Runtime Defense Shields:
        - ReaAndroidShield.kt   (JADX Overload Ambiguity Trap + InMemoryDexClassLoader)
        - rea_native_shield.hpp (C++ Compile-Time XOR Strings + Opaque Indirect Calls + Anti-Frida)
        - rea_flutter_shield.dart (Dart FFI Anti-Frida & Runtime String Unlocker)
        - ReaDotnetShield.cs    (.NET Anti-Debug + #US String Decryptor + RAM Assembly Host)
`);
}

function parseFlags(args) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positionals.push(a);
    }
  }
  return { command: positionals[0], target: positionals[1], flags };
}

function main() {
  const { command, target, flags } = parseFlags(process.argv.slice(2));

  if (!command || command === 'help' || flags.help) {
    printHelp();
    process.exit(0);
  }

  if (command === 'audit') {
    if (!target) throw new Error('Missing target path for `audit`');
    const report = auditTargetForRea(target);
    if (flags.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`\n[ANTI-REA AUDIT REPORT]`);
      console.log(`  Target        : ${report.target}`);
      console.log(`  Detected Type : ${report.detectedType}`);
      console.log(`  Exposure Score: ${report.reaExposureScore} / 100  -->  ${report.riskLevel}`);
      if (report.findings?.length) {
        console.log(`\n  Findings (${report.findings.length}):`);
        for (const f of report.findings) {
          console.log(`    - [${f.severity}] ${f.surface}: ${f.detail}`);
        }
      } else {
        console.log(`\n  Findings      : 0 static surfaces exposed to morluto/rea!`);
      }
      if (report.recommendations?.length) {
        console.log(`\n  Recommended Countermeasures:`);
        for (const r of report.recommendations) {
          console.log(`    * ${r}`);
        }
      }
      console.log('');
    }
    return;
  }

  if (command === 'lock') {
    if (!target) throw new Error('Missing input path for `lock`');
    const res = lockFile(target, {
      outputPath: flags.out,
      secret: flags.secret
    });
    console.log(`\n[ANTI-REA CODE-LOCK COMPLETE]`);
    console.log(`  Encrypted Vault : ${res.vaultPath} (${res.vaultSize} bytes)`);
    if (res.loaderPath) {
      console.log(`  Runtime Loader  : ${res.loaderPath}`);
    }
    console.log(`  Vault SHA-256   : ${res.sha256Vault}`);
    console.log(`  Unlock Secret   : ${res.secret}\n`);
    return;
  }

  if (command === 'unlock') {
    if (!target) throw new Error('Missing .realock path for `unlock`');
    if (!flags.secret) throw new Error('Missing `--secret <passphrase>` for `unlock`');
    const buf = fs.readFileSync(path.resolve(target));
    const plain = decryptRealockBuffer(buf, flags.secret);
    if (flags.out) {
      fs.writeFileSync(path.resolve(flags.out), plain);
      console.log(`Unlocked payload written to ${path.resolve(flags.out)} (${plain.length} bytes)`);
    } else {
      process.stdout.write(plain);
    }
    return;
  }

  if (command === 'armor') {
    if (!target) throw new Error('Missing target path for `armor`');
    const profile = flags.profile || 'js';
    const inPath = path.resolve(target);
    const outPath = flags.out ? path.resolve(flags.out) : `${inPath}.armored${path.extname(inPath)}`;

    if (profile === 'js') {
      const src = fs.readFileSync(inPath, 'utf8');
      const { armoredCode, encryptedStringsCount } = armorJavaScriptSource(src);
      fs.writeFileSync(outPath, armoredCode, 'utf8');
      console.log(`[ANTI-REA JS ARMOR] Encrypted ${encryptedStringsCount} AST/API/IPC literals -> ${outPath}`);
    } else if (profile === 'electron-fuses') {
      const buf = fs.readFileSync(inPath);
      const { armoredBuffer, changes } = armorElectronFusesInBuffer(buf);
      fs.writeFileSync(outPath, armoredBuffer);
      console.log(`[ANTI-REA ELECTRON FUSES] Hardened ${changes.length} fuses -> ${outPath}`);
    } else if (profile === 'flutter') {
      const buf = fs.readFileSync(inPath);
      const res = armorFlutterBinaryInBuffer(buf);
      fs.writeFileSync(outPath, res.armoredBuffer);
      console.log(
        `[ANTI-REA FLUTTER ARMOR] Scrubbed ${res.scrubbedPackageUris} package: URIs, anonymized ${res.anonymizedSnapshotHashes} snapshot hashes, masked ${res.maskedSymbols} symbols -> ${outPath}`
      );
    } else if (profile === 'dotnet') {
      const buf = fs.readFileSync(inPath);
      const res = armorDotnetBinaryInBuffer(buf);
      fs.writeFileSync(outPath, res.armoredBuffer);
      console.log(`[ANTI-REA .NET ARMOR] Masked BSJB CLI header (${res.bsjbMasked}) -> ${outPath}`);
    } else {
      throw new Error(`Unknown profile: ${profile}. Use js, electron-fuses, flutter, or dotnet.`);
    }
    return;
  }

  if (command === 'init-sdk') {
    const outDir = target || './sdk-shields';
    const res = generatePlatformShieldSdk(outDir);
    console.log(`\n[ANTI-REA PLATFORM SHIELDS GENERATED]`);
    for (const f of res.files) {
      console.log(`  + ${f}`);
    }
    console.log('');
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

try {
  main();
} catch (err) {
  console.error(`[ANTI-REA ERROR] ${err.message}`);
  process.exit(1);
}
