export {
  auditTargetForRea,
  inspectElectronFusesInBuffer,
  inspectFlutterAotInBuffer,
  inspectDotnetInBuffer,
  inspectJavaScriptSurface,
  ELECTRON_FUSE_SENTINEL,
  DART_SNAPSHOT_MAGIC_LE,
  DART_SNAPSHOT_MAGIC_BE,
  DOTNET_BSJB_MAGIC,
  REALOCK_MAGIC
} from './audit/reaAuditor.mjs';

export {
  CANONICAL_GUARD_SOURCE,
  computeGuardIntegrityDigest,
  deriveLockKey,
  encryptBufferToRealock,
  decryptRealockBuffer,
  compileJsToV8BytecodeBuffer,
  executeV8BytecodeBuffer,
  lockFile
} from './lock/codeLocker.mjs';

export {
  armorJavaScriptSource,
  armorElectronFusesInBuffer,
  armorFlutterBinaryInBuffer,
  injectElf64PtLoadConflict,
  hasConflictingElf64PtLoad,
  armorDotnetBinaryInBuffer,
  generatePlatformShieldSdk
} from './armor/reaArmor.mjs';
