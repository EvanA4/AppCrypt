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

    #endregion

    #region Operations

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
        throw new NotImplementedException();
    }

    /// <summary>
    /// Applies padding to <paramref name="data"/>
    /// using the data's own length, producing a byte array whose
    /// length is a whole multiple of <see cref="BlockSizeBytes"/>.
    /// </summary>
    internal static byte[] ApplyPadding(byte[] data) {
        throw new NotImplementedException();
    }

    #endregion

    #region Inner Calculations

    /// <summary>
    /// Applies the hashing algorithm to the padded data.
    /// </summary>
    internal static void ProcessData(uint[] state, byte[] paddedData) {
        throw new NotImplementedException();
    }

    #endregion

}
