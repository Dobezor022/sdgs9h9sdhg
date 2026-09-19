using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace FedMes.Desktop.Core.Security;

public sealed class WindowsDpapiSecretProtector : ISecretProtector
{
    private const int CryptProtectUiForbidden = 0x1;
    private const string DefaultPurpose = "FedMes.Desktop.AccountSecrets.v1";

    private readonly byte[] _optionalEntropy;

    public WindowsDpapiSecretProtector(string purpose = DefaultPurpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);

        byte[] purposeBytes = Encoding.UTF8.GetBytes(purpose);
        try
        {
            _optionalEntropy = SHA256.HashData(purposeBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(purposeBytes);
        }
    }

    public byte[] Protect(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.IsEmpty)
        {
            throw new ArgumentException("A secret cannot be empty.", nameof(plaintext));
        }

        return Transform(plaintext, protect: true);
    }

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData)
    {
        if (protectedData.IsEmpty)
        {
            throw new ArgumentException("Protected data cannot be empty.", nameof(protectedData));
        }

        return Transform(protectedData, protect: false);
    }

    private byte[] Transform(ReadOnlySpan<byte> source, bool protect)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows DPAPI is available only on Windows.");
        }

        DataBlob input = default;
        DataBlob entropy = default;
        DataBlob output = default;
        nint description = nint.Zero;

        try
        {
            input = AllocateBlob(source);
            entropy = AllocateBlob(_optionalEntropy);

            bool succeeded = protect
                ? CryptProtectData(
                    ref input,
                    null,
                    ref entropy,
                    nint.Zero,
                    nint.Zero,
                    CryptProtectUiForbidden,
                    out output)
                : CryptUnprotectData(
                    ref input,
                    out description,
                    ref entropy,
                    nint.Zero,
                    nint.Zero,
                    CryptProtectUiForbidden,
                    out output);

            if (!succeeded)
            {
                int error = Marshal.GetLastWin32Error();
                throw new CryptographicException(
                    "Windows DPAPI could not transform the protected value.",
                    new Win32Exception(error));
            }

            return CopyBlob(output);
        }
        finally
        {
            FreePrivateBlob(ref input);
            FreePrivateBlob(ref entropy);
            FreeLocalBlob(ref output);

            if (description != nint.Zero)
            {
                _ = LocalFree(description);
            }
        }
    }

    private static DataBlob AllocateBlob(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return default;
        }

        byte[] copy = source.ToArray();
        nint data = Marshal.AllocHGlobal(copy.Length);

        try
        {
            Marshal.Copy(copy, 0, data, copy.Length);
            return new DataBlob(copy.Length, data);
        }
        catch
        {
            ZeroUnmanaged(data, copy.Length);
            Marshal.FreeHGlobal(data);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    private static byte[] CopyBlob(DataBlob blob)
    {
        if (blob.Length <= 0 || blob.Data == nint.Zero)
        {
            throw new CryptographicException("Windows DPAPI returned an empty value.");
        }

        byte[] result = GC.AllocateUninitializedArray<byte>(blob.Length);
        Marshal.Copy(blob.Data, result, 0, result.Length);
        return result;
    }

    private static void FreePrivateBlob(ref DataBlob blob)
    {
        if (blob.Data == nint.Zero)
        {
            return;
        }

        ZeroUnmanaged(blob.Data, blob.Length);
        Marshal.FreeHGlobal(blob.Data);
        blob = default;
    }

    private static void FreeLocalBlob(ref DataBlob blob)
    {
        if (blob.Data == nint.Zero)
        {
            return;
        }

        ZeroUnmanaged(blob.Data, blob.Length);
        _ = LocalFree(blob.Data);
        blob = default;
    }

    private static void ZeroUnmanaged(nint address, int length)
    {
        if (address == nint.Zero || length <= 0)
        {
            return;
        }

        byte[] zeros = new byte[length];
        Marshal.Copy(zeros, 0, address, zeros.Length);
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DataBlob(int length, nint data)
    {
        public readonly int Length = length;
        public readonly nint Data = data;
    }

    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? dataDescription,
        ref DataBlob optionalEntropy,
        nint reserved,
        nint promptStructure,
        int flags,
        out DataBlob dataOut);

    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        out nint dataDescription,
        ref DataBlob optionalEntropy,
        nint reserved,
        nint promptStructure,
        int flags,
        out DataBlob dataOut);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern nint LocalFree(nint memory);
}
