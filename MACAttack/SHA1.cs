using System.Security.Cryptography;

namespace MACAttack;

/// <summary>
/// An implementation of SHA-1 as specified in FIPS 180-4.
/// </summary>
public static class SHA1 {

    #region Configuration

    /// <summary>SHA1 block size in bytes.</summary>
    public const int BlockSizeBytes = 64;

    /// <summary>SHA1 block size in words.</summary>
    public const int BlockSizeWords = 16;

    /// <summary>SHA1 digest size in bytes.</summary>
    public const int DigestSizeBytes = 20;

    /// <summary>SHA1 word size in bytes.</summary>
    public const int WordSizeBytes = 4;

    /// <summary>SHA1 initial hash state.</summary>
    public static readonly uint[] InitialHash = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

    #endregion

    #region Operations

    public static uint ROTL(uint x, int n)
    {
        return System.Numerics.BitOperations.RotateLeft(x, n);;
    }

    public static uint Ch(uint x, uint y, uint z)
    {
        return (x & y) ^ (~x & z);
    }

    public static uint Parity(uint x, uint y, uint z)
    {
        return x ^ y ^ z;
    }

    public static uint Maj(uint x, uint y, uint z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    public static uint F(int t, uint x, uint y, uint z)
    {
        if (t >= 0 && t <= 19) return Ch(x, y, z);
        if (t >= 20 && t <= 39) return Parity(x, y, z);
        if (t >= 40 && t <= 59) return Maj(x, y, z);
        return Parity(x, y, z);
    }

    public static uint[] ToInts(byte[] bytes)
    {
        uint[] output = new uint[bytes.Length / WordSizeBytes];

        for (int i = 0; i < output.Length; i++)
        {
            uint num = 0;
            for (int j = 0; j < WordSizeBytes; j++)
            {
                num = (num << 8) | bytes[i * WordSizeBytes + j];
            }
            output[i] = num;
        }

        return output;
    }

    public static byte[] ToBytes(uint[] words)
    {
        byte[] output = new byte[words.Length * WordSizeBytes];

        for (int i = 0; i < words.Length; i++)
        {
            uint word = words[i];
            for (int j = 0; j < WordSizeBytes; ++j)
            {
                output[i * WordSizeBytes + j] =
                    (byte) (word >> ((WordSizeBytes - 1 - j) * 8));
            }
        }

        return output;
    }

    public static uint GetWord(byte[] buffer, int wordIdx)
    {
        byte[] output = new byte[WordSizeBytes];
        for (int i = 0; i < WordSizeBytes; ++i) output[i] = buffer[wordIdx * WordSizeBytes + i];
        return ToInts(output)[0];
    }

    public static uint[] MessageSchedule(int i, byte[] paddedData)
    {
        uint[] output = new uint[80];

        for (int j = 0; j < BlockSizeWords; ++j) output[j] = GetWord(paddedData, i * BlockSizeWords + j);
        for (int j = 16; j < 80; ++j)
        {
            uint m3 = output[j-3];
            uint m8 = output[j-8];
            uint m14 = output[j-14];
            uint m16 = output[j-16];
            output[j] = ROTL(m3 ^ m8 ^ m14 ^ m16, 1);
        }

        return output;
    }

    public static uint GetK(int t)
    {
        if (t >= 0 && t <= 19) return 0x5a827999;
        if (t >= 20 && t <= 39) return 0x6ed9eba1;
        if (t >= 40 && t <= 59) return 0x8f1bbcdc;
        else return 0xca62c1d6;
    }

    /// <summary>
    /// Computes the standard SHA-1 digest of <paramref name="data"/>.
    /// </summary>
    /// <param name="data">Data to hash</param>
    /// <returns>The digest of the passed data.</returns>
    public static byte[] ComputeHash(byte[] data) {
        byte[] paddedData = ApplyPadding(data);
        uint[] state = (uint[]) InitialHash.Clone();
        ProcessData(state, paddedData);
        return ToBytes(state);
    }

    #endregion

    #region Padding

    /// <summary>
    /// Computes the SHA-1 padding that would be appended to a data of
    /// <paramref name="dataLengthBytes"/> bytes.
    /// </summary>
    internal static byte[] ComputePadding(long dataLengthBytes) {
        bool shouldExtend = dataLengthBytes % BlockSizeBytes >= BlockSizeBytes - 8;
        long toFillBlock = BlockSizeBytes - dataLengthBytes % BlockSizeBytes;
        byte[] output = new byte[shouldExtend ? 64 + toFillBlock : toFillBlock];
        output[0] = 0x80;
        byte[] lengthBytes = BitConverter.GetBytes(dataLengthBytes * 8);
        for (int i = 0; i < 8; ++i)
            output[output.Length - 1 - i] = lengthBytes[i];
        return output;
    }

    /// <summary>
    /// Applies padding to <paramref name="data"/>
    /// using the data's own length, producing a byte array whose
    /// length is a whole multiple of <see cref="BlockSizeBytes"/>.
    /// </summary>
    internal static byte[] ApplyPadding(byte[] data) {
        byte[] padding = ComputePadding(data.Length);
        byte[] output = new byte[padding.Length + data.Length];
        for (int i = 0; i < data.Length; ++i) output[i] = data[i];
        for (int i = 0; i < padding.Length; ++i) output[data.Length + i] = padding[i];
        return output;
    }

    #endregion

    #region Inner Calculations

    /// <summary>
    /// Applies the hashing algorithm to the padded data.
    /// </summary>
    internal static void ProcessData(uint[] state, byte[] paddedData) {
        int N = paddedData.Length / BlockSizeBytes;

        for (int i = 0; i < N; ++i)
        {
            uint[] messageSchedule = MessageSchedule(i, paddedData);
            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];
            uint T;

            for (int t = 0; t < 80; ++t)
            {
                T = ROTL(a, 5) + F(t, b, c, d) + e + GetK(t) + messageSchedule[t];
                e = d;
                d = c;
                c = ROTL(b, 30);
                b = a;
                a = T;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }
    }

    #endregion

}
