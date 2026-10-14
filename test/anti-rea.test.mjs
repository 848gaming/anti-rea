import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import {
  auditTargetForRea,
  ELECTRON_FUSE_SENTINEL,
  DART_SNAPSHOT_MAGIC_BE,
  DOTNET_BSJB_MAGIC,
  lockFile,
  decryptRealockBuffer,
  compileJsToV8BytecodeBuffer,
  executeV8BytecodeBuffer,
  armorJavaScriptSource,
  armorElectronFusesInBuffer,
  armorFlutterBinaryInBuffer,
  hasConflictingElf64PtLoad,
  armorDotnetBinaryInBuffer,
  generatePlatformShieldSdk
} from '../src/index.mjs';

test('1. JavaScript / Electron AST Armor v2.0 blinds REA static IPC, contextBridge, tRPC & GraphQL extractors + mangles identifiers while preserving runtime execution', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-js-'));
  const sampleJs = path.join(tmpDir, 'app.js');

  const originalSource = `
const ipcCalls = [];
const ipcMain = { handle: (ch, fn) => ipcCalls.push({ ch, res: fn() }) };
const contextBridge = { exposeInMainWorld: (key, api) => ipcCalls.push({ key, api }) };
const trpcClient = { invoice: { list: { useQuery: (arg) => ({ procedure: 'invoice.list', arg }) } } };

function computeSecretToken() {
  const secretPrefix = "Bearer sk_live_998877665544332211";
  return secretPrefix;
}

ipcMain.handle('auth:get-secret-token', () => computeSecretToken());
contextBridge.exposeInMainWorld('desktopVault', { version: 1 });
const queryResult = trpcClient.invoice.list.useQuery({ limit: 10 });
const gql = "query GetBillingAccount($id: ID!) { account(id: $id) { balance } }";
const endpoint = "https://api.internal.example.com/v1/keys";
//# sourceMappingURL=app.js.map
`;
  fs.writeFileSync(sampleJs, originalSource, 'utf8');

  // Step 1: Audit unarmored JS (should have high REA exposure score)
  const beforeAudit = auditTargetForRea(sampleJs);
  assert.ok(beforeAudit.reaExposureScore >= 70, `Expected high exposure score, got ${beforeAudit.reaExposureScore}`);

  // Step 2: Armor the JS source with v2.0 control-flow flattening + identifier mangling
  const { armoredCode, encryptedStringsCount, mangledIdentifiersCount } = armorJavaScriptSource(originalSource, {
    mangleIdentifiers: true,
    preserveIdentifiers: ['ipcCalls', 'trpcClient', 'queryResult', 'gql', 'endpoint']
  });
  assert.ok(encryptedStringsCount >= 6);
  assert.ok(mangledIdentifiersCount >= 2);
  assert.ok(!armoredCode.includes('computeSecretToken'), 'Internal function name should be mangled');

  const armoredPath = path.join(tmpDir, 'app.armored.js');
  fs.writeFileSync(armoredPath, armoredCode, 'utf8');

  // Step 3: Re-audit armored JS — REA static surface must drop to 0!
  const afterAudit = auditTargetForRea(armoredPath);
  assert.equal(afterAudit.reaExposureScore, 0, 'Armored JS should have 0 static exposure to REA');
  assert.equal(afterAudit.findings.length, 0);

  // Step 4: Execute the armored code to verify 100% functional equivalence!
  const fn = new Function(`${armoredCode}\nreturn { ipcCalls, queryResult, gql, endpoint };`);
  const runtimeResult = fn();
  assert.equal(runtimeResult.ipcCalls[0].ch, 'auth:get-secret-token');
  assert.equal(runtimeResult.ipcCalls[0].res, 'Bearer sk_live_998877665544332211');
  assert.equal(runtimeResult.ipcCalls[1].key, 'desktopVault');
  assert.equal(runtimeResult.queryResult.procedure, 'invoice.list');
  assert.ok(runtimeResult.gql.includes('query GetBillingAccount'));
  assert.equal(runtimeResult.endpoint, 'https://api.internal.example.com/v1/keys');
});

test('2. Electron Fuse Hardener flips fuse wire to block REA --inspect and RunAsNode', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-fuses-'));
  const mockElectronBin = path.join(tmpDir, 'Electron.exe');

  const header = Buffer.from('MZ\x90\x00MockElectronExecutablePadding');
  const wireMeta = Buffer.from([0x01, 0x06]);
  const unhardenedWire = Buffer.from('101100', 'utf8');
  const binBuf = Buffer.concat([header, ELECTRON_FUSE_SENTINEL, wireMeta, unhardenedWire, Buffer.alloc(64)]);
  fs.writeFileSync(mockElectronBin, binBuf);

  const beforeAudit = auditTargetForRea(mockElectronBin);
  assert.equal(beforeAudit.detectedType, 'electron-binary');
  assert.equal(beforeAudit.fuseAudit.fuses.EnableNodeCliInspectArguments, 'ENABLED');

  const { armoredBuffer, changes } = armorElectronFusesInBuffer(binBuf);
  assert.equal(changes.length, 6);
  const armoredBinPath = path.join(tmpDir, 'Electron.hardened.exe');
  fs.writeFileSync(armoredBinPath, armoredBuffer);

  const afterAudit = auditTargetForRea(armoredBinPath);
  assert.equal(afterAudit.fuseAudit.fuses.EnableNodeCliInspectArguments, 'DISABLED');
  assert.equal(afterAudit.fuseAudit.fuses.RunAsNode, 'DISABLED');
  assert.equal(afterAudit.reaExposureScore, 0);
});

test('3. Flutter libapp.so AOT Armor scrubs package: URIs, snapshot hashes, and _kDart*Snapshot* symbols with exact byte-length preservation', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-flutter-'));
  const mockLibApp = path.join(tmpDir, 'libapp.so');

  const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
  const symbols = Buffer.from('_kDartVmSnapshotData\0_kDartIsolateSnapshotData\0', 'utf8');
  const snapshotHeader = Buffer.concat([
    DART_SNAPSHOT_MAGIC_BE,
    Buffer.alloc(16, 0x03),
    Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f90', 'utf8')
  ]);
  const stringPool = Buffer.from(
    '\0package:my_fintech_app/services/crypto_wallet.dart\0package:my_fintech_app/api/auth_client.dart\0',
    'utf8'
  );
  const originalBuf = Buffer.concat([elfHeader, symbols, snapshotHeader, stringPool]);
  fs.writeFileSync(mockLibApp, originalBuf);

  const beforeAudit = auditTargetForRea(mockLibApp);
  assert.equal(beforeAudit.reaExposureScore, 100);

  const { armoredBuffer, scrubbedPackageUris, anonymizedSnapshotHashes, maskedSymbols } =
    armorFlutterBinaryInBuffer(originalBuf);

  assert.equal(armoredBuffer.length, originalBuf.length);
  assert.equal(scrubbedPackageUris, 2);
  assert.equal(anonymizedSnapshotHashes, 1);
  assert.equal(maskedSymbols, 2);

  const armoredPath = path.join(tmpDir, 'libapp.armored.so');
  fs.writeFileSync(armoredPath, armoredBuffer);

  const afterAudit = auditTargetForRea(armoredPath);
  assert.equal(afterAudit.reaExposureScore, 0);
});

test('4. .NET Managed Assembly Armor & REALOCK AES-256-GCM Vault Packer', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-dotnet-'));
  const mockDll = path.join(tmpDir, 'CoreLogic.dll');

  const bsjbHeader = Buffer.alloc(32);
  DOTNET_BSJB_MAGIC.copy(bsjbHeader, 0);
  bsjbHeader.writeUInt32LE(12, 12);
  Buffer.from('v4.0.30319\0\0', 'utf8').copy(bsjbHeader, 16);
  const streamsBuf = Buffer.from('#~\0#Strings\0#US\0MyCompany.PaymentEngine.SecretValidator\0', 'utf8');
  const dllBuf = Buffer.concat([Buffer.from('MZ\x90\x00'), bsjbHeader, streamsBuf]);
  fs.writeFileSync(mockDll, dllBuf);

  const { armoredBuffer, bsjbMasked } = armorDotnetBinaryInBuffer(dllBuf);
  assert.equal(bsjbMasked, true);
  const armoredDll = path.join(tmpDir, 'CoreLogic.armored.dll');
  fs.writeFileSync(armoredDll, armoredBuffer);
  const midAudit = auditTargetForRea(armoredDll);
  assert.notEqual(midAudit.detectedType, 'dotnet-managed-assembly');

  const lockRes = lockFile(mockDll, { secret: 'super-secret-hardware-key', tamperBound: false });
  const lockedAudit = auditTargetForRea(lockRes.vaultPath);
  assert.equal(lockedAudit.detectedType, 'realock-encrypted-container');
  assert.equal(lockedAudit.reaExposureScore, 0);

  const vaultBytes = fs.readFileSync(lockRes.vaultPath);
  const unlockedBytes = decryptRealockBuffer(vaultBytes, 'super-secret-hardware-key');
  assert.deepEqual(unlockedBytes, dllBuf);
});

test('5. Multi-platform SDK generation emits Android, C++, Flutter, and .NET shields', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-sdk-'));
  const res = generatePlatformShieldSdk(tmpDir);
  assert.equal(res.files.length, 4);
  for (const f of res.files) {
    assert.ok(fs.existsSync(f), `Expected generated file ${f} to exist`);
  }
});

test('6. [v2.0] Cryptographic Tamper-Bound Key Derivation + V8 Bytecode (.jsc) fails decryption if anti-debug guard is patched', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-tamper-'));
  const secretModulePath = path.join(tmpDir, 'paymentKernel.cjs');
  fs.writeFileSync(
    secretModulePath,
    `exports.processPayment = (amount) => ({ status: 'AUTHORIZED', amount, vault: 'v2-bytecode' });`,
    'utf8'
  );

  // Lock in V8 Bytecode mode with Tamper-Bound Guard enabled
  const lockRes = lockFile(secretModulePath, {
    secret: 'tamper-bound-master-secret',
    v8Bytecode: true
  });
  assert.equal(lockRes.v8Bytecode, true);
  assert.equal(lockRes.tamperBoundGuard, true);

  // Import the generated .locked.mjs and execute the V8 bytecode payload in memory
  const loaderUrl = pathToFileURL(lockRes.loaderPath).href;
  const loaderMod = await import(loaderUrl);
  const exportedApi = loaderMod.executeLockedModule();
  assert.deepEqual(exportedApi.processPayment(250), {
    status: 'AUTHORIZED',
    amount: 250,
    vault: 'v2-bytecode'
  });

  // Now simulate an attacker patching `__verifyCleanRuntime` inside `.locked.mjs` to bypass anti-debug checks!
  const originalLoaderCode = fs.readFileSync(lockRes.loaderPath, 'utf8');
  const tamperedLoaderCode = originalLoaderCode.replace(
    `if (inspector.url() !== undefined)`,
    `if (false /* patched by attacker */)`
  );
  const tamperedLoaderPath = path.join(tmpDir, 'tampered.locked.mjs');
  fs.writeFileSync(tamperedLoaderPath, tamperedLoaderCode, 'utf8');

  const tamperedMod = await import(pathToFileURL(tamperedLoaderPath).href);
  // Because __verifyCleanRuntime.toString() changed, HKDF-SHA256 derives a wrong AES-256-GCM key!
  assert.throws(
    () => tamperedMod.executeLockedModule(),
    /Unsupported state or unable to authenticate data/,
    'Tampering with __verifyCleanRuntime must break AES-256-GCM key derivation!'
  );
});

test('7. [v2.0] V8 Cached Bytecode (.jsc) contains 0 UTF-8 JS source strings and executes cleanly', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-jsc-'));
  const source = `
    const superSecretEndpoint = "https://internal.vault.example/v2/signing-key";
    exports.getEndpoint = () => superSecretEndpoint;
  `;
  const jscBuf = compileJsToV8BytecodeBuffer(source);
  const jscPath = path.join(tmpDir, 'module.jsc');
  fs.writeFileSync(jscPath, jscBuf);

  // Audit the .jsc file — must score 0 exposure
  const audit = auditTargetForRea(jscPath);
  assert.equal(audit.detectedType, 'v8-bytecode-bundle');
  assert.equal(audit.reaExposureScore, 0);

  // Execute the V8 bytecode buffer without source code
  const res = executeV8BytecodeBuffer(jscBuf);
  assert.equal(res.getEndpoint(), 'https://internal.vault.example/v2/signing-key');
});

test('8. [v2.0] Flutter Safe-dlsym ELF64 PT_LOAD Conflict Injection blinds REA while keeping _kDart* symbols intact for libflutter.so', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-elf64-'));
  const mockElfPath = path.join(tmpDir, 'libapp_elf64.so');

  // Construct a valid 64-bit LE ELF header (64 bytes) + 2 program headers (2 * 56 = 112 bytes)
  const elfHeader = Buffer.alloc(64);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]).copy(elfHeader, 0);
  elfHeader.writeBigUInt64LE(64n, 32); // e_phoff = 64
  elfHeader.writeUInt16LE(56, 54); // e_phentsize = 56
  elfHeader.writeUInt16LE(2, 56); // e_phnum = 2

  // Program Header 0: PT_LOAD (p_type = 1)
  const ph0 = Buffer.alloc(56);
  ph0.writeUInt32LE(1, 0); // PT_LOAD
  ph0.writeUInt32LE(5, 4); // PF_R | PF_X
  ph0.writeBigUInt64LE(0n, 8); // p_offset = 0
  ph0.writeBigUInt64LE(0x10000n, 16); // p_vaddr = 0x10000
  ph0.writeBigUInt64LE(0x10000n, 24); // p_paddr
  ph0.writeBigUInt64LE(0x8000n, 32); // p_filesz
  ph0.writeBigUInt64LE(0x8000n, 40); // p_memsz
  ph0.writeBigUInt64LE(0x1000n, 48); // p_align

  // Program Header 1: PT_NOTE (p_type = 4) spare slot
  const ph1 = Buffer.alloc(56);
  ph1.writeUInt32LE(4, 0); // PT_NOTE

  const payload = Buffer.concat([
    Buffer.from('_kDartVmSnapshotData\0_kDartIsolateSnapshotData\0', 'utf8'),
    DART_SNAPSHOT_MAGIC_BE,
    Buffer.alloc(16, 0x03),
    Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f90', 'utf8'),
    Buffer.from('\0package:bank_app/core/vault.dart\0', 'utf8')
  ]);

  const fullElf = Buffer.concat([elfHeader, ph0, ph1, payload]);
  fs.writeFileSync(mockElfPath, fullElf);

  const beforeAudit = auditTargetForRea(mockElfPath);
  assert.equal(beforeAudit.reaExposureScore, 100);

  // Armor in safeDlsym mode (keeps _kDart* symbol names for stock libflutter.so, injects PT_LOAD conflict)
  const armored = armorFlutterBinaryInBuffer(fullElf, { safeDlsym: true });
  assert.equal(armored.ptLoadConflictInjected, true);
  assert.equal(armored.maskedSymbols, 0, 'safeDlsym must preserve _kDart* symbol names');
  assert.ok(armored.armoredBuffer.includes(Buffer.from('_kDartIsolateSnapshotData', 'utf8')));
  assert.equal(hasConflictingElf64PtLoad(armored.armoredBuffer), true);

  const armoredElfPath = path.join(tmpDir, 'libapp_elf64.armored.so');
  fs.writeFileSync(armoredElfPath, armored.armoredBuffer);

  const afterAudit = auditTargetForRea(armoredElfPath);
  assert.equal(afterAudit.reaExposureScore, 0, 'ELF64 with PT_LOAD conflict + scrubbed URIs/hashes must score 0');
});
