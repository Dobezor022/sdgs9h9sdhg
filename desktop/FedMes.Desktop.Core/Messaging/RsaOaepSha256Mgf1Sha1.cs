using System.Numerics;
using System.Security.Cryptography;

namespace FedMes.Desktop.Core.Messaging;

/// <summary>
/// Implements the exact OAEP parameters used by Android Keystore in FedMes:
/// SHA-256 for OAEP and SHA-1 for MGF1. The built-in .NET OAEP helper does not
/// expose an independent MGF1 digest, so protocol compatibility requires the
/// encoding step to be implemented explicitly.
/// </summary>
internal static class RsaOaepSha256Mgf1Sha1
{
    private const int HashLength = 32;

    public static byte[] Encrypt(RSA publicKey, ReadOnlySpan<byte> plaintext, RandomNumberGenerator random)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(random);
        RSAParameters parameters = publicKey.ExportParameters(includePrivateParameters: false);
        try
        {
            int modulusLength = parameters.Modulus?.Length ?? throw new CryptographicException("RSA modulus is missing.");
            if (plaintext.Length > modulusLength - (2 * HashLength) - 2)
            {
                throw new CryptographicException("Message key is too large for RSA-OAEP.");
            }

            byte[] encoded = OaepEncode(plaintext, modulusLength, random);
            try
            {
                return RawPublicOperation(encoded, parameters);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
        finally
        {
            Clear(parameters);
        }
    }

    public static byte[] Decrypt(RSA privateKey, ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        RSAParameters parameters = privateKey.ExportParameters(includePrivateParameters: true);
        try
        {
            int modulusLength = parameters.Modulus?.Length ?? throw new CryptographicException("RSA modulus is missing.");
            if (ciphertext.Length != modulusLength)
            {
                throw new CryptographicException("RSA ciphertext has an invalid size.");
            }

            byte[] encoded = RawPrivateOperation(ciphertext, parameters);
            try
            {
                return OaepDecode(encoded);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
        finally
        {
            Clear(parameters);
        }
    }

    private static byte[] OaepEncode(ReadOnlySpan<byte> plaintext, int modulusLength, RandomNumberGenerator random)
    {
        byte[] labelHash = SHA256.HashData(Array.Empty<byte>());
        byte[] dataBlock = new byte[modulusLength - HashLength - 1];
        byte[] seed = new byte[HashLength];
        byte[] dataMask = [];
        byte[] seedMask = [];
        try
        {
            labelHash.CopyTo(dataBlock, 0);
            int delimiterIndex = dataBlock.Length - plaintext.Length - 1;
            dataBlock[delimiterIndex] = 1;
            plaintext.CopyTo(dataBlock.AsSpan(delimiterIndex + 1));
            random.GetBytes(seed);
            dataMask = Mgf1Sha1(seed, dataBlock.Length);
            XorInPlace(dataBlock, dataMask);
            seedMask = Mgf1Sha1(dataBlock, HashLength);
            XorInPlace(seed, seedMask);

            byte[] encoded = new byte[modulusLength];
            seed.CopyTo(encoded, 1);
            dataBlock.CopyTo(encoded, 1 + HashLength);
            return encoded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(labelHash);
            CryptographicOperations.ZeroMemory(dataBlock);
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(dataMask);
            CryptographicOperations.ZeroMemory(seedMask);
        }
    }

    private static byte[] OaepDecode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < (2 * HashLength) + 2 || encoded[0] != 0)
        {
            throw new CryptographicException("RSA-OAEP decoding failed.");
        }

        byte[] maskedSeed = encoded.Slice(1, HashLength).ToArray();
        byte[] maskedDataBlock = encoded[(1 + HashLength)..].ToArray();
        byte[] seedMask = [];
        byte[] dataMask = [];
        byte[] expectedLabelHash = SHA256.HashData(Array.Empty<byte>());
        try
        {
            seedMask = Mgf1Sha1(maskedDataBlock, HashLength);
            XorInPlace(maskedSeed, seedMask);
            dataMask = Mgf1Sha1(maskedSeed, maskedDataBlock.Length);
            XorInPlace(maskedDataBlock, dataMask);

            if (!CryptographicOperations.FixedTimeEquals(
                    maskedDataBlock.AsSpan(0, HashLength),
                    expectedLabelHash))
            {
                throw new CryptographicException("RSA-OAEP label hash is invalid.");
            }

            int delimiter = -1;
            for (int index = HashLength; index < maskedDataBlock.Length; index++)
            {
                byte value = maskedDataBlock[index];
                if (delimiter < 0 && value == 1)
                {
                    delimiter = index;
                    break;
                }

                if (value != 0)
                {
                    throw new CryptographicException("RSA-OAEP padding is invalid.");
                }
            }

            if (delimiter < 0 || delimiter == maskedDataBlock.Length - 1)
            {
                throw new CryptographicException("RSA-OAEP delimiter is missing.");
            }

            return maskedDataBlock[(delimiter + 1)..];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(maskedSeed);
            CryptographicOperations.ZeroMemory(maskedDataBlock);
            CryptographicOperations.ZeroMemory(seedMask);
            CryptographicOperations.ZeroMemory(dataMask);
            CryptographicOperations.ZeroMemory(expectedLabelHash);
        }
    }

    private static byte[] RawPublicOperation(ReadOnlySpan<byte> encoded, RSAParameters parameters)
    {
        BigInteger message = new(encoded, isUnsigned: true, isBigEndian: true);
        BigInteger exponent = new(parameters.Exponent ?? throw new CryptographicException("RSA exponent is missing."), true, true);
        BigInteger modulus = new(parameters.Modulus ?? throw new CryptographicException("RSA modulus is missing."), true, true);
        BigInteger result = BigInteger.ModPow(message, exponent, modulus);
        return ToFixedUnsignedBigEndian(result, parameters.Modulus.Length);
    }

    private static byte[] RawPrivateOperation(ReadOnlySpan<byte> ciphertext, RSAParameters parameters)
    {
        BigInteger encrypted = new(ciphertext, isUnsigned: true, isBigEndian: true);
        BigInteger privateExponent = new(parameters.D ?? throw new CryptographicException("RSA private exponent is missing."), true, true);
        BigInteger modulus = new(parameters.Modulus ?? throw new CryptographicException("RSA modulus is missing."), true, true);
        if (encrypted >= modulus)
        {
            throw new CryptographicException("RSA ciphertext representative is out of range.");
        }

        BigInteger result = BigInteger.ModPow(encrypted, privateExponent, modulus);
        return ToFixedUnsignedBigEndian(result, parameters.Modulus.Length);
    }

    private static byte[] ToFixedUnsignedBigEndian(BigInteger value, int size)
    {
        byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length > size)
        {
            CryptographicOperations.ZeroMemory(raw);
            throw new CryptographicException("RSA representative is larger than the modulus.");
        }

        byte[] output = new byte[size];
        raw.CopyTo(output, size - raw.Length);
        CryptographicOperations.ZeroMemory(raw);
        return output;
    }

    private static byte[] Mgf1Sha1(ReadOnlySpan<byte> seed, int length)
    {
        byte[] mask = new byte[length];
        byte[] input = new byte[seed.Length + 4];
        seed.CopyTo(input);
        int offset = 0;
        uint counter = 0;
        try
        {
            while (offset < length)
            {
                input[^4] = (byte)(counter >> 24);
                input[^3] = (byte)(counter >> 16);
                input[^2] = (byte)(counter >> 8);
                input[^1] = (byte)counter;
#pragma warning disable CA5350 // SHA-1 is required only as the MGF1 digest by the Android OAEP protocol.
                byte[] digest = SHA1.HashData(input);
#pragma warning restore CA5350
                try
                {
                    int count = Math.Min(digest.Length, length - offset);
                    digest.AsSpan(0, count).CopyTo(mask.AsSpan(offset, count));
                    offset += count;
                    counter++;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(digest);
                }
            }

            return mask;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static void XorInPlace(Span<byte> target, ReadOnlySpan<byte> mask)
    {
        if (target.Length != mask.Length)
        {
            throw new ArgumentException("Mask length must equal target length.", nameof(mask));
        }

        for (int index = 0; index < target.Length; index++)
        {
            target[index] ^= mask[index];
        }
    }

    private static void Clear(RSAParameters parameters)
    {
        Clear(parameters.D);
        Clear(parameters.DP);
        Clear(parameters.DQ);
        Clear(parameters.Exponent);
        Clear(parameters.InverseQ);
        Clear(parameters.Modulus);
        Clear(parameters.P);
        Clear(parameters.Q);
    }

    private static void Clear(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
