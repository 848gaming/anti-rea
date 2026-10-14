import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  auditTargetForRea,
  ELECTRON_FUSE_SENTINEL,
  DART_SNAPSHOT_MAGIC_BE,
  DOTNET_BSJB_MAGIC,
  lockFile,
  armorJavaScriptSource,
  armorElectronFusesInBuffer,
  armorFlutterBinaryInBuffer
} from '../src/index.mjs';

const demoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-rea-demo-'));
console.log(`========================================================================`);
console.log(`  ANTI-REA LIVE DEMO: Defeating morluto/rea Across App Targets`);
console.log(`  Workspace: ${demoDir}`);
console.log(`========================================================================\n`);

// 1. Flutter AOT Binary (libapp.so)
const flutterPath = path.join(demoDir, 'libapp.so');
const flutterBuf = Buffer.concat([
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
  Buffer.from('_kDartVmSnapshotData\0_kDartIsolateSnapshotData\0', 'utf8'),
  DART_SNAPSHOT_MAGIC_BE,
  Buffer.alloc(16, 0x03),
  Buffer.from('a1b2c3d4e5f60718293a4b5c6d7e8f90', 'utf8'),
  Buffer.from('\0package:acme_wallet/crypto/signing_service.dart\0package:acme_wallet/api/rpc.dart\0', 'utf8')
]);
fs.writeFileSync(flutterPath, flutterBuf);

console.log(`[1] FLUTTER AOT BINARY (libapp.so)`);
const flutterBefore = auditTargetForRea(flutterPath);
console.log(`    Before Armor -> REA Exposure Score: ${flutterBefore.reaExposureScore}/100 (${flutterBefore.riskLevel})`);
const armoredFlutter = armorFlutterBinaryInBuffer(flutterBuf);
const flutterArmoredPath = path.join(demoDir, 'libapp.armored.so');
fs.writeFileSync(flutterArmoredPath, armoredFlutter.armoredBuffer);
const flutterAfter = auditTargetForRea(flutterArmoredPath);
console.log(`    After Armor  -> REA Exposure Score: ${flutterAfter.reaExposureScore}/100 (${flutterAfter.riskLevel})`);
console.log(`    Scrubbed ${armoredFlutter.scrubbedPackageUris} package: URIs & masked ${armoredFlutter.maskedSymbols} Dart snapshot symbols.\n`);

// 2. Electron / JS Bundle
const jsPath = path.join(demoDir, 'bundle.js');
const jsCode = `
ipcMain.handle('vault:decrypt-seed', () => 'secret');
contextBridge.exposeInMainWorld('vaultBridge', {});
const data = trpc.wallet.transfer.useMutation();
const query = "mutation TransferFunds($amt: Int!) { transfer(amt: $amt) { ok } }";
const api = "https://api.acme-wallet.internal/v1/transfer";
//# sourceMappingURL=bundle.js.map
`;
fs.writeFileSync(jsPath, jsCode, 'utf8');

console.log(`[2] JAVASCRIPT / ELECTRON BUNDLE (bundle.js)`);
const jsBefore = auditTargetForRea(jsPath);
console.log(`    Before Armor -> REA Exposure Score: ${jsBefore.reaExposureScore}/100 (${jsBefore.riskLevel})`);
const { armoredCode } = armorJavaScriptSource(jsCode);
const jsArmoredPath = path.join(demoDir, 'bundle.armored.js');
fs.writeFileSync(jsArmoredPath, armoredCode, 'utf8');
const jsAfter = auditTargetForRea(jsArmoredPath);
console.log(`    After Armor  -> REA Exposure Score: ${jsAfter.reaExposureScore}/100 (${jsAfter.riskLevel})`);

// 3. Cryptographic Code-Lock (.realock)
const locked = lockFile(jsArmoredPath, { secret: 'hardware-derived-master-key' });
const lockedAudit = auditTargetForRea(locked.vaultPath);
console.log(`[3] CRYPTOGRAPHIC CODE-LOCK (.realock AES-256-GCM + HKDF-SHA256)`);
console.log(`    Vault File   -> ${path.basename(locked.vaultPath)} (${locked.vaultSize} bytes)`);
console.log(`    Loader File  -> ${path.basename(locked.loaderPath)}`);
console.log(`    Vault Audit  -> REA Exposure Score: ${lockedAudit.reaExposureScore}/100 (${lockedAudit.riskLevel})\n`);
