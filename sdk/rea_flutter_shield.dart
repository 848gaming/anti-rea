// Anti-REA Flutter / Dart FFI Shield (rea_flutter_shield.dart)
// Complements 'anti-rea armor libapp.so --profile flutter' with runtime anti-Frida & vault unlocking.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

typedef _VerifyNativeC = ffi.Bool Function();
typedef _VerifyNativeDart = bool Function();

class ReaFlutterShield {
  static ffi.DynamicLibrary? _lib;

  /// Loads the native anti-REA shield library and verifies no Frida / LLDB tracer is attached.
  static bool verifyCleanEnvironment() {
    if (Platform.isAndroid || Platform.isLinux) {
      try {
        final maps = File('/proc/self/maps').readAsStringSync();
        if (maps.contains('frida') || maps.contains('gum-js-loop')) {
          return false;
        }
      } catch (_) {}
    }
    try {
      _lib ??= Platform.isAndroid
          ? ffi.DynamicLibrary.open('librea_native_shield.so')
          : ffi.DynamicLibrary.process();
      final verifyFn = _lib!
          .lookupFunction<_VerifyNativeC, _VerifyNativeDart>('verifyNativeIntegrityAndAntiFrida');
      return verifyFn();
    } catch (_) {
      return true;
    }
  }

  /// De-obfuscates runtime strings protected with anti-rea rolling XOR
  static String unlockObfuscatedString(String base64Cipher, List<int> key) {
    final raw = base64Decode(base64Cipher);
    final out = Uint8List(raw.length);
    for (var i = 0; i < raw.length; i++) {
      out[i] = raw[i] ^ key[i % key.length] ^ ((i * 31) & 0xff);
    }
    return utf8.decode(out);
  }
}
