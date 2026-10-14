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
  deriveLockKey,
  encryptBufferToRealock,
  decryptRealockBuffer,
  lockFile
} from './lock/codeLocker.mjs';

export {
  armorJavaScriptSource,
  armorElectronFusesInBuffer,
  armorFlutterBinaryInBuffer,
  armorDotnetBinaryInBuffer,
  generatePlatformShieldSdk
} from './armor/reaArmor.mjs';
