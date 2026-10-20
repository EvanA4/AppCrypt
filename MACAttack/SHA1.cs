using System.Security.Cryptography;

namespace MACAttack;

/// <summary>
/// An implementation of SHA-1 as specified in FIPS 180-4.
/// </summary>
public static class SHA1 {

    #region Configuration

    /// <summary>SHA1 block size in bytes.</summary>
    public const int BlockSizeBytes = 64;

    /// <summary>SHA1 digest size in bytes.</summary>
    public const int DigestSizeBytes = 20;

    /// <summary>SHA1 word size in bytes.</summary>
    public const int WordSizeBytes = 4;

    /// <summary>SHA1 initial hash state.</summary>
    public static readonly uint[] InitialHash = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

    #endregion

    #region Operations

    public static byte[] ROTL(byte[] x, int n)
    {
        int wholeBytes = n / 8 % WordSizeBytes;
        int subByte = n % 8;

        // Rotate whole bytes
        byte[] output = new byte[WordSizeBytes];
        for (int i = 0; i < WordSizeBytes; ++i) output[(i + wholeBytes) % WordSizeBytes] = x[i];
        if (subByte == 0) return output;

        // Rotate to make bits higher order
        byte tmp = (byte) ((output[0] >> (8 - subByte)) & 0xFF);
        for (int i = 0; i < WordSizeBytes; ++i)
        {
            output[i] <<= subByte;
            if (i != WordSizeBytes - 1) output[i] |= (byte) ((output[i+1] >> (8 - subByte)) & 0xFF);
            else output[i] |= tmp;
        }

        return output;
    }

    public static byte[] ROTR(int n, byte[] x)
    {
        return ROTL(x, WordSizeBytes * 8 - n);
    }

    public static byte[] AddWords(byte[] a, byte[] b)
    {
        byte[] output = new byte[WordSizeBytes];

        int carry = 0;
        for (int i = WordSizeBytes - 1; i >= 0; i--)
        {
            int sum = a[i] + b[i] + carry;
            output[i] = (byte) sum;
            carry = sum >> 8;
        }

        return output;
    }

    public static byte[] NotWord(byte[] w)
    {
        byte[] output = new byte[WordSizeBytes];
        for (int i = 0; i < WordSizeBytes; ++i) output[i] = (byte) (~w[i] & 0xFF);
        return output;
    }

    public static byte[] XORWords(byte[] a, byte[] b)
    {
        byte[] output = new byte[WordSizeBytes];
        for (int i = 0; i < WordSizeBytes; ++i) output[i] = (byte) ((a[i] ^ b[i]) & 0xFF);
        return output;
    }

    public static byte[] AndWords(byte[] a, byte[] b)
    {
        byte[] output = new byte[WordSizeBytes];
        for (int i = 0; i < WordSizeBytes; ++i) output[i] = (byte) (a[i] & b[i] & 0xFF);
        return output;
    }

    public static byte[] OrWords(byte[] a, byte[] b)
    {
        byte[] output = new byte[WordSizeBytes];
        for (int i = 0; i < WordSizeBytes; ++i) output[i] = (byte) ((a[i] | b[i]) & 0xFF);
        return output;
    }

    public static byte[] Ch(byte[] x, byte[] y, byte[] z)
    {
        return XORWords(AndWords(x, y), AndWords(NotWord(x), z));
    }

    public static byte[] Parity(byte[] x, byte[] y, byte[] z)
    {
        return XORWords(XORWords(x, y), z);
    }

    public static byte[] Maj(byte[] x, byte[] y, byte[] z)
    {
        return XORWords(XORWords(AndWords(x, y), AndWords(x, z)), AndWords(y, z));
    }

    public static byte[] F(int t, byte[] x, byte[] y, byte[] z)
    {
        if (t >= 0 && t <= 19) return Ch(x, y, z);
        if (t >= 20 && t <= 39) return Parity(x, y, z);
        if (t >= 40 && t <= 59) return Maj(x, y, z);
        return Parity(x, y, z);
    }

    public static byte[] GetWord(byte[] buffer, int wordIdx)
    {
        byte[] output = new byte[WordSizeBytes];
        for (int i = 0; i < WordSizeBytes; ++i) output[i] = buffer[wordIdx * WordSizeBytes + i];
        return output;
    }

    public static byte[] MessageSchedule(int i, byte[] paddedData)
    {
        byte[] output = new byte[80 * WordSizeBytes];

        for (int j = 0; j < BlockSizeBytes; ++j) output[j] = paddedData[i * BlockSizeBytes + j];
        for (int j = 16; j < 80; ++j)
        {
            byte[] m3 = GetWord(output, j - 3);
            byte[] m8 = GetWord(output, j - 8);
            byte[] m14 = GetWord(output, j - 14);
            byte[] m16 = GetWord(output, j - 16);
            byte[] tmp = ROTL(XORWords(XORWords(XORWords(m3, m8), m14), m16), 1);            
            for (int k = 0; k < WordSizeBytes; ++k) output[j * WordSizeBytes + k] = tmp[k];
        }

        return output;
    }

    public static byte[] ToWords(uint[] nums)
    {
        var output = new byte[nums.Length * WordSizeBytes];

        for (int i = 0; i < nums.Length; i++)
        {
            uint num = nums[i];
            for (int j = 0; j < WordSizeBytes; ++j)
            {
                output[i * WordSizeBytes + j] =
                    (byte) (num >> ((WordSizeBytes - 1 - j) * 8));
            }
        }

        return output;
    }

    /// <summary>
    /// Computes the standard SHA-1 digest of <paramref name="data"/>.
    /// </summary>
    /// <param name="data">Data to hash</param>
    /// <returns>The digest of the passed data.</returns>
    public static byte[] ComputeHash(byte[] data) {
        throw new NotImplementedException();
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
        byte[] stateBytes = ToWords(state);
        byte[] a = GetWord(stateBytes, 0);
    }

    #endregion

}
