import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';
import v8 from 'node:v8';
import { REALOCK_MAGIC } from '../audit/reaAuditor.mjs';

/**
 * Canonical source of the runtime anti-REA / anti-debug / anti-Frida verification function.
 * Its normalized text is SHA-256 hashed and mixed directly into HKDF-SHA256 key derivation!
 * If an attacker modifies even 1 character of this function in `.locked.mjs`, the derived
 * AES-256-GCM key changes and decryption mathematically fails with an authentication tag error.
 */
export const CANONICAL_GUARD_SOURCE = `function __verifyCleanRuntime() {
  if (inspector.url() !== undefined) {
    throw new Error('[ANTI-REA LOCK] Runtime inspector detected. Aborting vault unlock.');
  }
  const argv = process.execArgv.join(' ') + ' ' + (process.env.NODE_OPTIONS || '');
  if (/--(inspect|inspect-brk|debug|prof)/i.test(argv)) {
    throw new Error('[ANTI-REA LOCK] Debug flags detected in process arguments.');
  }
  if (process.env.LD_PRELOAD || process.env.DYLD_INSERT_LIBRARIES || process.env.FRIDA_AGENT) {
    throw new Error('[ANTI-REA LOCK] Dynamic instrumentation environment variable detected.');
  }
  const fnToString = Function.prototype.toString;
  const nativeTargets = [fnToString, Object.defineProperty, Reflect.apply, JSON.parse, Uint8Array.prototype.subarray];
  for (let i = 0; i < nativeTargets.length; i++) {
    if (!fnToString.call(nativeTargets[i]).includes('[native code]')) {
      throw new Error('[ANTI-REA LOCK] V8 intrinsic API hook detected (Frida/MonkeyPatch).');
    }
  }
}`;

export function computeGuardIntegrityDigest(guardSource = CANONICAL_GUARD_SOURCE) {
  const normalized = guardSource.replace(/\s+/g, ' ').trim();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

/**
 * Derives a 256-bit AES-GCM key using HKDF-SHA256 from master secret + salt + context binding.
 */
export function deriveLockKey(secret, salt, contextInfo = 'anti-rea-code-lock-v2') {
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      Buffer.from(secret, 'utf8'),
      salt,
      Buffer.from(contextInfo, 'utf8'),
      32
    )
  );
}

/**
 * Encrypts a Buffer into a binary `.realock` container.
 * Layout:
 *   [0..4]    Magic: "RLCK\x01" (5 bytes)
 *   [5..36]   HKDF Salt (32 bytes)
 *   [37..48]  AES-GCM IV (12 bytes)
 *   [49..64]  AES-GCM Auth Tag (16 bytes)
 *   [65..96]  Plaintext SHA-256 Commitment (32 bytes)
 *   [97..N]   AES-256-GCM Ciphertext
 */
export function encryptBufferToRealock(plaintextBuf, secret, contextInfo = 'anti-rea-code-lock-v2') {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const key = deriveLockKey(secret, salt, contextInfo);

  const plaintextHash = crypto.createHash('sha256').update(plaintextBuf).digest();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(plaintextHash);

  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  key.fill(0); // Zero key in RAM immediately

  return Buffer.concat([
    REALOCK_MAGIC,
    salt,
    iv,
    authTag,
    plaintextHash,
    ciphertext
  ]);
}

/**
 * Decrypts and verifies a `.realock` container Buffer in memory.
 */
export function decryptRealockBuffer(realockBuf, secret, contextInfo = 'anti-rea-code-lock-v2') {
  if (realockBuf.length < 97 || !realockBuf.subarray(0, 5).equals(REALOCK_MAGIC)) {
    throw new Error('Invalid REALOCK container header');
  }

  const salt = realockBuf.subarray(5, 37);
  const iv = realockBuf.subarray(37, 49);
  const authTag = realockBuf.subarray(49, 65);
  const expectedHash = realockBuf.subarray(65, 97);
  const ciphertext = realockBuf.subarray(97);

  const key = deriveLockKey(secret, salt, contextInfo);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(expectedHash);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const actualHash = crypto.createHash('sha256').update(plaintext).digest();

    if (!crypto.timingSafeEqual(expectedHash, actualHash)) {
      throw new Error('REALOCK plaintext commitment mismatch');
    }

    return plaintext;
  } finally {
    key.fill(0); // Always scrub derived key from memory
  }
}

/**
 * Compiles JavaScript source into V8 binary cached bytecode (`.jsc` envelope) so NO UTF-8
 * JavaScript source code is shipped at all. REA's AST parser and Wakaru cannot parse V8 bytecode.
 */
export function compileJsToV8BytecodeBuffer(sourceCode) {
  v8.setFlagsFromString('--no-lazy');
  v8.setFlagsFromString('--no-flush-bytecode');
  const wrappedSource = `(function (exports, require, module, __filename, __dirname) { ${sourceCode}\n});`;
  const script = new vm.Script(wrappedSource, {
    filename: 'protected-module.jsc',
    produceCachedData: true
  });
  const cachedData = script.createCachedData();
  const header = Buffer.alloc(12);
  header.write('RJSC', 0, 4, 'utf8');
  header.writeUInt32LE(wrappedSource.length, 4);
  header.writeUInt32LE(cachedData.length, 8);
  return Buffer.concat([header, cachedData]);
}

/**
 * Executes a V8 bytecode buffer (`RJSC` header + V8 cachedData) without any original source text!
 */
export function executeV8BytecodeBuffer(jscBuf, sandboxContext = {}) {
  if (jscBuf.length < 12 || jscBuf.subarray(0, 4).toString('utf8') !== 'RJSC') {
    throw new Error('Invalid RJSC V8 bytecode buffer');
  }
  const sourceLength = jscBuf.readUInt32LE(4);
  const cachedLen = jscBuf.readUInt32LE(8);
  const cachedData = jscBuf.subarray(12, 12 + cachedLen);

  // V8 matches cachedData against source length only; we pass blank spaces instead of source code!
  const dummySource = ' '.repeat(sourceLength);
  const script = new vm.Script(dummySource, {
    filename: 'protected-module.jsc',
    cachedData,
     produceCachedData: false
  });
  if (script.cachedDataRejected) {
    throw new Error('V8 bytecode cachedData was rejected (Node.js V8 version mismatch)');
  }
  const compiledWrapper = script.runInThisContext();
  const mod = { exports: {} };
  compiledWrapper(
    mod.exports,
    sandboxContext.require || (() => {}),
    mod,
    sandboxContext.__filename || 'protected-module.jsc',
    sandboxContext.__dirname || process.cwd()
  );
  return mod.exports;
}

/**
 * Locks a target file into a `.realock` container and optionally generates a self-defending
 * runtime loader stub (`.locked.mjs`) that uses Cryptographic Tamper-Bound Key Derivation
 * (mixing the SHA-256 hash of `__verifyCleanRuntime.toString()` into HKDF-SHA256) and optional
 * V8 bytecode compilation (`options.v8Bytecode = true`).
 */
export function lockFile(inputPath, options = {}) {
  const resolvedInput = path.resolve(inputPath);
  const rawInput = fs.readFileSync(resolvedInput);
  const secret = options.secret || crypto.randomBytes(24).toString('hex');
  const baseContext = options.contextInfo || 'anti-rea-code-lock-v2';

  // Bind the SHA-256 digest of __verifyCleanRuntime into the HKDF context when generating a loader
  const useTamperBoundGuard = options.tamperBound !== false;
  const guardDigest = computeGuardIntegrityDigest(CANONICAL_GUARD_SOURCE);
  const effectiveContext = useTamperBoundGuard ? `${baseContext}:guard=${guardDigest}` : baseContext;

  const isBytecode = Boolean(options.v8Bytecode);
  const payloadToEncrypt = isBytecode
    ? compileJsToV8BytecodeBuffer(rawInput.toString('utf8'))
    : rawInput;

  const outLockPath = options.outputPath
    ? path.resolve(options.outputPath)
    : `${resolvedInput}.realock`;

  const lockedBuf = encryptBufferToRealock(payloadToEncrypt, secret, effectiveContext);
  fs.writeFileSync(outLockPath, lockedBuf);

  // Split the secret into two XOR shares so the secret never appears as a literal string in the loader
  const secretBytes = Buffer.from(secret, 'utf8');
  const maskBytes = crypto.randomBytes(secretBytes.length);
  const shareBytes = Buffer.alloc(secretBytes.length);
  for (let i = 0; i < secretBytes.length; i++) {
    shareBytes[i] = secretBytes[i] ^ maskBytes[i];
  }

  let loaderPath = null;
  if (options.emitLoader !== false) {
    loaderPath = `${resolvedInput}.locked.mjs`;
    const relVault = path.basename(outLockPath);
    const loaderCode = generateProtectedJsLoader({
      relVault,
      maskHex: maskBytes.toString('hex'),
      shareHex: shareBytes.toString('hex'),
      baseContext,
      useTamperBoundGuard,
      isBytecode
    });
    fs.writeFileSync(loaderPath, loaderCode, 'utf8');
  }

  return {
    inputPath: resolvedInput,
    vaultPath: outLockPath,
    loaderPath,
    originalSize: rawInput.length,
    vaultSize: lockedBuf.length,
    v8Bytecode: isBytecode,
    tamperBoundGuard: useTamperBoundGuard,
    guardDigest,
    secret,
    sha256Vault: crypto.createHash('sha256').update(lockedBuf).digest('hex')
  };
}

function generateProtectedJsLoader({
  relVault,
  maskHex,
  shareHex,
  baseContext,
  useTamperBoundGuard,
  isBytecode
}) {
  return `// Generated by anti-rea v2.0 Code-Lock Vault Packer
// Protected by Cryptographic Tamper-Bound Key Derivation: modifying __verifyCleanRuntime
// alters its SHA-256 digest and causes AES-256-GCM key derivation to fail mathematically.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import inspector from 'node:inspector';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

${CANONICAL_GUARD_SOURCE}

export function unlockVaultPayload(customSecret) {
  __verifyCleanRuntime();
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const vaultBuf = fs.readFileSync(path.join(__dirname, ${JSON.stringify(relVault)}));

  let secretBuf;
  if (customSecret) {
    secretBuf = Buffer.from(customSecret, 'utf8');
  } else {
    const m = Buffer.from(${JSON.stringify(maskHex)}, 'hex');
    const s = Buffer.from(${JSON.stringify(shareHex)}, 'hex');
    secretBuf = Buffer.alloc(m.length);
    for (let i = 0; i < m.length; i++) secretBuf[i] = m[i] ^ s[i];
  }

  // Compute live SHA-256 of __verifyCleanRuntime.toString() so any patch breaks the AES-256-GCM key!
  const guardNormalized = __verifyCleanRuntime.toString().replace(/\\s+/g, ' ').trim();
  const liveGuardDigest = crypto.createHash('sha256').update(guardNormalized, 'utf8').digest('hex');
  const contextStr = ${useTamperBoundGuard}
    ? ${JSON.stringify(baseContext)} + ':guard=' + liveGuardDigest
    : ${JSON.stringify(baseContext)};

  const salt = vaultBuf.subarray(5, 37);
  const iv = vaultBuf.subarray(37, 49);
  const authTag = vaultBuf.subarray(49, 65);
  const expectedHash = vaultBuf.subarray(65, 97);
  const ciphertext = vaultBuf.subarray(97);

  const key = Buffer.from(
    crypto.hkdfSync('sha256', secretBuf, salt, Buffer.from(contextStr, 'utf8'), 32)
  );
  secretBuf.fill(0);

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(expectedHash);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    key.fill(0);
  }
}

export function executeLockedModule(sandboxContext = {}) {
  const unlockedBuf = unlockVaultPayload();
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  try {
    if (${isBytecode}) {
      const sourceLength = unlockedBuf.readUInt32LE(4);
      const cachedLen = unlockedBuf.readUInt32LE(8);
      const cachedData = unlockedBuf.subarray(12, 12 + cachedLen);
      const script = new vm.Script(' '.repeat(sourceLength), {
        filename: 'protected-module.jsc',
        cachedData
      });
      if (script.cachedDataRejected) {
        throw new Error('[ANTI-REA LOCK] V8 bytecode rejected by runtime.');
      }
      const fn = script.runInThisContext();
      const mod = { exports: {} };
      fn(mod.exports, sandboxContext.require || (() => {}), mod, __filename, __dirname);
      return mod.exports;
    } else {
      const code = unlockedBuf.toString('utf8');
      const cjsWrapper = new Function('exports', 'require', 'module', '__filename', '__dirname', code);
      const mod = { exports: {} };
      cjsWrapper(mod.exports, sandboxContext.require || (() => {}), mod, __filename, __dirname);
      return mod.exports;
    }
  } finally {
    unlockedBuf.fill(0);
  }
}
`;
}
