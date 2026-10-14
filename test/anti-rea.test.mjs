import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  auditTargetForRea,
  ELECTRON_FUSE_SENTINEL,
  DART_SNAPSHOT_MAGIC_BE,
  DOTNET_BSJB_MAGIC,
  lockFile,
  decryptRealockBuffer,
  armorJavaScriptSource,
  armorElectronFusesInBuffer,
  armorFlutterBinaryInBuffer,
  armorDotnetBinaryInBuffer,
  generatePlatformShieldSdk
} from '../src/index.mjs';

test('1. JavaScript / Electron AST Armor blinds REA static IPC, contextBridge, tRPC & GraphQL extractors while preserving runtime execution', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-js-'));
  const sampleJs = path.join(tmpDir, 'app.js');

  const originalSource = `
const ipcCalls = [];
const ipcMain = { handle: (ch, fn) => ipcCalls.push({ ch, res: fn() }) };
const contextBridge = { exposeInMainWorld: (key, api) => ipcCalls.push({ key, api }) };
const trpcClient = { invoice: { list: { useQuery: (arg) => ({ procedure: 'invoice.list', arg }) } } };

ipcMain.handle('auth:get-secret-token', () => 'Bearer sk_live_998877665544332211');
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
  assert.ok(beforeAudit.findings.some((f) => f.surface.includes('IPC')));
  assert.ok(beforeAudit.findings.some((f) => f.surface.includes('tRPC')));
  assert.ok(beforeAudit.findings.some((f) => f.surface.includes('GraphQL')));
  assert.ok(beforeAudit.findings.some((f) => f.surface.includes('SourceMap')));

  // Step 2: Armor the JS source
  const { armoredCode, encryptedStringsCount } = armorJavaScriptSource(originalSource);
  assert.ok(encryptedStringsCount >= 6);
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

  // Construct a mock PE binary containing the official Electron Fuse Sentinel + unhardened wire
  // Wire: RunAsNode='1', CookieEnc='0', NodeOptions='1', CliInspect='1', AsarIntegrity='0', OnlyFromAsar='0'
  const header = Buffer.from('MZ\x90\x00MockElectronExecutablePadding');
  const wireMeta = Buffer.from([0x01, 0x06]); // version 1, length 6
  const unhardenedWire = Buffer.from('101100', 'utf8');
  const binBuf = Buffer.concat([header, ELECTRON_FUSE_SENTINEL, wireMeta, unhardenedWire, Buffer.alloc(64)]);
  fs.writeFileSync(mockElectronBin, binBuf);

  const beforeAudit = auditTargetForRea(mockElectronBin);
  assert.equal(beforeAudit.detectedType, 'electron-binary');
  assert.equal(beforeAudit.fuseAudit.fuses.EnableNodeCliInspectArguments, 'ENABLED');
  assert.equal(beforeAudit.fuseAudit.fuses.RunAsNode, 'ENABLED');
  assert.ok(beforeAudit.reaExposureScore >= 60);

  // Armor the Electron fuse wire
  const { armoredBuffer, changes } = armorElectronFusesInBuffer(binBuf);
  assert.equal(changes.length, 6);
  const armoredBinPath = path.join(tmpDir, 'Electron.hardened.exe');
  fs.writeFileSync(armoredBinPath, armoredBuffer);

  const afterAudit = auditTargetForRea(armoredBinPath);
  assert.equal(afterAudit.fuseAudit.fuses.EnableNodeCliInspectArguments, 'DISABLED');
  assert.equal(afterAudit.fuseAudit.fuses.RunAsNode, 'DISABLED');
  assert.equal(afterAudit.fuseAudit.fuses.EnableEmbeddedAsarIntegrityValidation, 'ENABLED');
  assert.equal(afterAudit.fuseAudit.fuses.OnlyLoadAppFromAsar, 'ENABLED');
  assert.equal(afterAudit.reaExposureScore, 0);
});

test('3. Flutter libapp.so AOT Armor scrubs package: URIs, snapshot hashes, and _kDart*Snapshot* symbols with exact byte-length preservation', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-flutter-'));
  const mockLibApp = path.join(tmpDir, 'libapp.so');

  // Build mock ELF with _kDartIsolateSnapshotData, 0xf5f5dcdc magic + 20-byte header + 32-byte SDK hash, and package: URIs
  const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
  const symbols = Buffer.from('_kDartVmSnapshotData\0_kDartIsolateSnapshotData\0', 'utf8');
  const snapshotHeader = Buffer.concat([
    DART_SNAPSHOT_MAGIC_BE,
    Buffer.alloc(16, 0x03), // 4 + 16 = 20 bytes up to hash
    Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f90', 'utf8') // 32-char hex snapshot hash
  ]);
  const stringPool = Buffer.from(
    '\0package:my_fintech_app/services/crypto_wallet.dart\0package:my_fintech_app/api/auth_client.dart\0',
    'utf8'
  );
  const originalBuf = Buffer.concat([elfHeader, symbols, snapshotHeader, stringPool]);
  fs.writeFileSync(mockLibApp, originalBuf);

  const beforeAudit = auditTargetForRea(mockLibApp);
  assert.equal(beforeAudit.detectedType, 'flutter-aot-library');
  assert.equal(beforeAudit.flutterAudit.packageUris.length, 2);
  assert.equal(beforeAudit.flutterAudit.snapshotHashes[0], 'a1b2c3d4e5f60718293a4b5c6d7e8f90');
  assert.equal(beforeAudit.reaExposureScore, 100);

  // Armor Flutter binary
  const { armoredBuffer, scrubbedPackageUris, anonymizedSnapshotHashes, maskedSymbols } =
    armorFlutterBinaryInBuffer(originalBuf);

  // Exact byte length must be preserved so ELF offsets never shift
  assert.equal(armoredBuffer.length, originalBuf.length);
  assert.equal(scrubbedPackageUris, 2);
  assert.equal(anonymizedSnapshotHashes, 1);
  assert.equal(maskedSymbols, 2);

  const armoredPath = path.join(tmpDir, 'libapp.armored.so');
  fs.writeFileSync(armoredPath, armoredBuffer);

  const afterAudit = auditTargetForRea(armoredPath);
  assert.equal(afterAudit.flutterAudit, undefined);
  assert.equal(afterAudit.reaExposureScore, 0);
});

test('4. .NET Managed Assembly Armor & REALOCK AES-256-GCM Vault Packer', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-dotnet-'));
  const mockDll = path.join(tmpDir, 'CoreLogic.dll');

  // Create a mock .NET PE/CLI buffer with BSJB signature and #Strings / #US streams
  const bsjbHeader = Buffer.alloc(32);
  DOTNET_BSJB_MAGIC.copy(bsjbHeader, 0);
  bsjbHeader.writeUInt32LE(12, 12);
  Buffer.from('v4.0.30319\0\0', 'utf8').copy(bsjbHeader, 16);
  const streamsBuf = Buffer.from('#~\0#Strings\0#US\0MyCompany.PaymentEngine.SecretValidator\0', 'utf8');
  const dllBuf = Buffer.concat([Buffer.from('MZ\x90\x00'), bsjbHeader, streamsBuf]);
  fs.writeFileSync(mockDll, dllBuf);

  const beforeAudit = auditTargetForRea(mockDll);
  assert.equal(beforeAudit.detectedType, 'dotnet-managed-assembly');
  assert.ok(beforeAudit.reaExposureScore >= 70);

  // Armor BSJB header
  const { armoredBuffer, bsjbMasked } = armorDotnetBinaryInBuffer(dllBuf);
  assert.equal(bsjbMasked, true);
  const armoredDll = path.join(tmpDir, 'CoreLogic.armored.dll');
  fs.writeFileSync(armoredDll, armoredBuffer);
  const midAudit = auditTargetForRea(armoredDll);
  assert.notEqual(midAudit.detectedType, 'dotnet-managed-assembly');

  // Lock into AES-256-GCM .realock container
  const lockRes = lockFile(mockDll, { secret: 'super-secret-hardware-key' });
  const lockedAudit = auditTargetForRea(lockRes.vaultPath);
  assert.equal(lockedAudit.detectedType, 'realock-encrypted-container');
  assert.equal(lockedAudit.reaExposureScore, 0);

  // Verify decryption round-trip matches original byte-for-byte
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
