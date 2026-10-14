// Anti-REA .NET Managed & NativeAOT Shield (ReaDotnetShield.cs)
// Countermeasures against morluto/rea inspect_managed_artifact & inspect_managed_members:
// 1. Encrypts assemblies into a .realock AES-256-GCM envelope loaded via Assembly.Load(byte[]) in RAM
//    (morluto/rea explicitly cannot unpack encrypted hosts or non-PE/CLI containers).
// 2. Replaces #US (0x70 ldstr) user string literals with runtime XOR/AES vault lookups.
// 3. Detects managed & native debuggers before unlocking the assembly.

using System;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace AntiRea.Shield
{
    public static class ReaDotnetShield
    {
        public static void AssertCleanRuntime()
        {
            if (Debugger.IsAttached || Debugger.IsLogging())
            {
                throw new InvalidOperationException("[ANTI-REA] Managed debugger detected.");
            }
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CORECLR_ENABLE_PROFILING")))
            {
                throw new InvalidOperationException("[ANTI-REA] CLR Profiler hook detected.");
            }
        }

        public static string UnlockUserString(string base64Blob, byte[] key)
        {
            AssertCleanRuntime();
            byte[] raw = Convert.FromBase64String(base64Blob);
            byte[] plain = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++)
            {
                plain[i] = (byte)(raw[i] ^ key[i % key.Length] ^ ((i * 31) & 0xFF));
            }
            return Encoding.UTF8.GetString(plain);
        }

        public static Assembly LoadRealockAssembly(byte[] realockBytes, byte[] aesKey)
        {
            AssertCleanRuntime();
            if (realockBytes.Length < 97 ||
                realockBytes[0] != (byte)'R' || realockBytes[1] != (byte)'L' ||
                realockBytes[2] != (byte)'C' || realockBytes[3] != (byte)'K')
            {
                throw new CryptographicException("Invalid REALOCK header");
            }

            ReadOnlySpan<byte> iv = new ReadOnlySpan<byte>(realockBytes, 37, 12);
            ReadOnlySpan<byte> tag = new ReadOnlySpan<byte>(realockBytes, 49, 16);
            ReadOnlySpan<byte> aad = new ReadOnlySpan<byte>(realockBytes, 65, 32);
            ReadOnlySpan<byte> cipher = new ReadOnlySpan<byte>(realockBytes, 97, realockBytes.Length - 97);

            byte[] rawAssembly = new byte[cipher.Length];
            using var aes = new AesGcm(aesKey, 16);
            aes.Decrypt(iv, cipher, tag, rawAssembly, aad);

            return Assembly.Load(rawAssembly);
        }
    }
}
