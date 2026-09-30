using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AsymmetricCryptography;

/// <summary>
/// MGF1, the mask generation function from RFC 8017 §B.2.1. It stretches a seed into an
/// arbitrarily long pseudorandom mask by hashing <c>seed || counter</c> for counter = 0, 1, 2, ...
/// and concatenating the digests.
/// </summary>
internal static class MGF1 {

    /// <summary>
    /// Fills <paramref name="mask"/> with MGF1 output derived from <paramref name="seed"/>.
    /// </summary>
    /// <param name="hash">The hash driving MGF1. Left in a reset state on return.</param>
    /// <param name="seed">The seed to stretch. May be empty.</param>
    /// <param name="mask">Destination buffer, filled completely.</param>
    private static void Fill(IncrementalHash hash, ReadOnlySpan<byte> seed, Span<byte> mask) {
        Span<byte> counter = stackalloc byte[4];
        Span<byte> block = stackalloc byte[hash.HashLengthInBytes];

        for (uint i = 0; !mask.IsEmpty; i++) {
            BinaryPrimitives.WriteUInt32BigEndian(counter, i);

            // AppendData of an empty span is a no-op, so an empty seed still produces the
            // well-defined mask Hash(counter) - matching the spec rather than throwing.
            hash.AppendData(seed);
            hash.AppendData(counter);
            hash.GetHashAndReset(block);

            // The final block is usually a partial one, hence the min.
            var n = Math.Min(hash.HashLengthInBytes, mask.Length);
            block[..n].CopyTo(mask);
            mask = mask[n..];
        }
    }

    /// <summary>
    /// XORs MGF1 output derived from <paramref name="seed"/> into <paramref name="data"/> in
    /// place. Applying this twice with the same seed is the identity, which is why masking and
    /// unmasking are the same operation.
    /// </summary>
    /// <param name="hash">The hash driving MGF1.</param>
    /// <param name="seed">The seed to stretch. Must not overlap <paramref name="data"/>.</param>
    /// <param name="data">The buffer to mask in place.</param>
    internal static void XorInto(IncrementalHash hash, ReadOnlySpan<byte> seed, Span<byte> data) {
        var mask = new byte[data.Length];
        Fill(hash, seed, mask);
        for (var i = 0; i < data.Length; i++)
            data[i] ^= mask[i];
    }
}

/// <summary>
/// RSAES-OAEP encoding and decoding (RFC 8017 §7.1). OAEP turns a short message into a
/// full-modulus-width block that is randomized, so encrypting the same message twice gives
/// different ciphertexts, and structurally checkable, so a mauled ciphertext is rejected
/// rather than decrypted into garbage.
/// </summary>
/// <remarks>
/// <see cref="Decode"/> reports failures by throwing and is not constant time, so the
/// distinctions it draws between failure modes are useful for teaching but would be a
/// Manger/Bleichenbacher-style oracle in production.
/// </remarks>
public sealed class OAEPEncoder {

    /// <summary>Hash used for the label digest and to size the seed.</summary>
    private readonly IncrementalHash hashAlgorithm;

    /// <summary>Hash used inside MGF1 when masking.</summary>
    private readonly IncrementalHash mgfHashAlgorithm;

    /// <summary>Digest of the label, recomputed never - it is fixed at construction.</summary>
    private readonly byte[] labelDigest;

    /// <summary>
    /// Smallest encoded block, in bytes: the leading <c>0x00</c>, <c>hLen</c> for the seed,
    /// <c>hLen</c> for the label digest, and 1 for the mandatory <c>0x01</c> separator.
    /// That is 66 bytes with SHA-256 and 130 with SHA-512.
    /// </summary>
    private int MinPaddingBytes => 2 * hashAlgorithm.HashLengthInBytes + 2;

    /// <summary>
    /// Creates an encoder using one hash for both the label digest and MGF1.
    /// </summary>
    /// <param name="hash">Hash to use throughout.</param>
    /// <param name="label">Optional label (the "L" of OAEP); must match on decode. Rarely used.</param>
    public OAEPEncoder(HashAlgorithmName hash,
                       ReadOnlySpan<byte> label = default) : this(hash, hash, label) { }

    /// <summary>
    /// Creates an encoder with separate hashes for the label digest and MGF1.
    /// </summary>
    /// <param name="hash">Hash for the label digest; also sets the seed length.</param>
    /// <param name="mgfHash">Hash used inside MGF1.</param>
    /// <param name="label">Optional label (the "L" of OAEP); must match on decode.</param>
    public OAEPEncoder(HashAlgorithmName hash,
                       HashAlgorithmName mgfHash,
                       ReadOnlySpan<byte> label = default) {
        hashAlgorithm = IncrementalHash.CreateHash(hash);
        mgfHashAlgorithm = IncrementalHash.CreateHash(mgfHash);

        hashAlgorithm.AppendData(label);
        labelDigest = hashAlgorithm.GetHashAndReset();
    }

    /// <summary>
    /// Largest message, in bytes, that fits in an encoded block of
    /// <paramref name="outputLength"/> bytes.
    /// </summary>
    /// <param name="outputLength">Encoded block size, normally the modulus byte count.</param>
    /// <returns>
    /// The message capacity. This is negative when <paramref name="outputLength"/> is smaller
    /// than the padding overhead, which callers should treat as "no message fits".
    /// </returns>
    public int GetMaxMessageLength(int outputLength) =>
        outputLength - MinPaddingBytes;

    /// <summary>
    /// Encodes a message as <c>EM = 0x00 || maskedSeed || maskedDB</c>.
    /// </summary>
    /// <param name="message">The message to encode. May be empty.</param>
    /// <param name="outputLength">Length of the encoded block in bytes.</param>
    /// <returns>A newly allocated block of <paramref name="outputLength"/> bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="outputLength"/> is too small to hold the padding, or
    /// <paramref name="message"/> is longer than <see cref="GetMaxMessageLength"/> allows.
    /// </exception>
    public byte[] Encode(ReadOnlySpan<byte> message, int outputLength) {
        if (outputLength < MinPaddingBytes)
            throw new ArgumentOutOfRangeException(nameof(outputLength),
                "Output will not have enough room to write necessary padding.");
        if (message.Length > GetMaxMessageLength(outputLength))
            throw new ArgumentOutOfRangeException(nameof(message), "Message too long for the requested encoded length.");

        // EM = 0x00 || maskedSeed || maskedDB. The leading zero byte is what keeps EM, read
        // big-endian, strictly below the RSA modulus.
        var encodedMessage = new byte[outputLength];
        var seed = encodedMessage.AsSpan(1, hashAlgorithm.HashLengthInBytes);
        var db = encodedMessage.AsSpan(1 + hashAlgorithm.HashLengthInBytes);

        // DB = labelDigest || PS(zeros) || 0x01 || message
        labelDigest.CopyTo(db);
        db[hashAlgorithm.HashLengthInBytes..].Clear();
        db[^(message.Length + 1)] = 0x01;
        message.CopyTo(db[^message.Length..]);

        // maskedDB = DB xor MGF1(seed);  maskedSeed = seed xor MGF1(maskedDB)
        RandomNumberGenerator.Fill(seed);
        MGF1.XorInto(mgfHashAlgorithm, seed, db);
        MGF1.XorInto(mgfHashAlgorithm, db, seed);

        return encodedMessage;
    }

    /// <summary>
    /// Reverses <see cref="Encode"/>, validating the leading byte, the label digest, and the
    /// zero padding before returning the message.
    /// </summary>
    /// <param name="encodedMessage">The encoded block.</param>
    /// <returns>The recovered message, which may be empty.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The block is shorter than the padding overhead.</exception>
    /// <exception cref="ArgumentException">
    /// The leading byte is not <c>0x00</c>, the label digest does not match, or the padding
    /// section is malformed.
    /// </exception>
    public byte[] Decode(ReadOnlySpan<byte> encodedMessage) {
        if (encodedMessage.Length < MinPaddingBytes)
            throw new ArgumentOutOfRangeException(nameof(encodedMessage), "Encoded message is the wrong length.");
        if (encodedMessage[0] != 0x00)
            throw new ArgumentException("First byte of encoded message was not 0x00", nameof(encodedMessage));

        // Unmask in the reverse order of Encode: the seed first (its mask comes from the
        // still-masked DB), then DB using the recovered seed. The spans are named for their
        // incoming contents; after these two calls they hold seed and DB respectively.
        var buffer = encodedMessage.ToArray();
        var maskedSeed = buffer.AsSpan(1, hashAlgorithm.HashLengthInBytes);
        var maskedDB = buffer.AsSpan(1 + hashAlgorithm.HashLengthInBytes);
        MGF1.XorInto(mgfHashAlgorithm, maskedDB, maskedSeed);   // -> seed
        MGF1.XorInto(mgfHashAlgorithm, maskedSeed, maskedDB);   // -> DB

        if (!CryptographicOperations.FixedTimeEquals(maskedDB[..hashAlgorithm.HashLengthInBytes], labelDigest))
            throw new ArgumentException("Label data was not correct in encoded message.", nameof(encodedMessage));

        // DB = lHash || PS(0x00 ...) || 0x01 || M
        for (int i = hashAlgorithm.HashLengthInBytes; i < maskedDB.Length; i++) {
            if (maskedDB[i] == 0x01) { return maskedDB[(i + 1)..].ToArray(); }
            if (maskedDB[i] != 0x00)
                throw new ArgumentException("Encoded message contained invalid bytes in the DB section (byte not 0x01 or 0x00).", nameof(encodedMessage));
        }

        throw new ArgumentException("Encoded message was missing a separator byte in the DB section.", nameof(encodedMessage));
    }
}

/// <summary>
/// RSASSA-PSS encoding and verification (RFC 8017 §9.1). PSS salts each signature, so signing
/// the same message twice produces different signatures, and it has a tight security proof in
/// the random oracle model - unlike the deterministic PKCS#1 v1.5 scheme it replaced.
/// </summary>
public sealed class PSSEncoder {

    /// <summary>Hash used for the message digest and for H.</summary>
    private readonly IncrementalHash hashAlgorithm;

    /// <summary>Hash used inside MGF1 when masking DB.</summary>
    private readonly IncrementalHash mgfHashAlgorithm;

    /// <summary>
    /// Smallest encoded block, in bytes: <c>hLen</c> for H, <c>hLen</c> for the salt,
    /// plus 2 for the mandatory <c>0x01</c> separator and the trailing <c>0xBC</c>.
    /// <para>
    /// This is the same bound as <see cref="OAEPEncoder"/>'s, which is why a modulus
    /// large enough for one encoding is large enough for the other: 66 bytes (528 bits)
    /// with SHA-256, 130 bytes (1040 bits) with SHA-512.
    /// </para>
    /// </summary>
    private int MinPaddingBytes => 2 * hashAlgorithm.HashLengthInBytes + 2;

    /// <summary>
    /// Creates an encoder using one hash everywhere, which is what interoperable
    /// implementations expect.
    /// </summary>
    /// <param name="hash">Hash to use for the digest, for H, and inside MGF1.</param>
    public PSSEncoder(HashAlgorithmName hash) : this(hash, hash) { }

    /// <summary>Creates an encoder with a distinct MGF1 hash.</summary>
    /// <param name="hash">Hash used for the message digest and for H.</param>
    /// <param name="mgfHash">Hash inside MGF1. Defaults to <paramref name="hash"/>, which is
    /// what every mainstream implementation (and the BCL) assumes. This is the one hash in
    /// PSS that RFC 8017 genuinely allows to differ.</param>
    public PSSEncoder(HashAlgorithmName hash, HashAlgorithmName mgfHash) {
        hashAlgorithm = IncrementalHash.CreateHash(hash);
        mgfHashAlgorithm = IncrementalHash.CreateHash(mgfHash);
    }

    #region Encoding

    /// <summary>
    /// Hashes <paramref name="data"/> and encodes the digest as
    /// <c>EM = maskedDB || H || 0xBC</c>, with the salt length fixed at the digest length.
    /// </summary>
    /// <param name="data">The data to sign. It is hashed here, not by the caller.</param>
    /// <param name="outputBitLength">
    /// Size of the encoded block in bits, normally one less than the modulus bit length. Any
    /// bits in the top byte beyond this count are zeroed so the block stays below the modulus.
    /// </param>
    /// <returns>A newly allocated block of <c>ceil(outputBitLength / 8)</c> bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="outputBitLength"/> is not positive, or is too small for the padding.
    /// </exception>
    public byte[] Encode(ReadOnlySpan<byte> data, int outputBitLength) {
        if (outputBitLength < 1)
            throw new ArgumentOutOfRangeException(nameof(outputBitLength), "Output bit length must be positive.");
        if (outputBitLength < (MinPaddingBytes * 8))
            throw new ArgumentOutOfRangeException(nameof(outputBitLength),
                "Output will not have enough room to write necessary padding.");

        var outputByteCount = (outputBitLength + 7) / 8;
        var spareBits = (8 * outputByteCount) - outputBitLength;

        hashAlgorithm.AppendData(data);
        var digest = hashAlgorithm.GetHashAndReset();

        // Generate a random salt. This is why signing the same message always results in a different signature.
        var salt = new byte[hashAlgorithm.HashLengthInBytes];
        RandomNumberGenerator.Fill(salt);

        // EM = maskedDB || H || 0xBC
        var encodedMessage = new byte[outputByteCount];
        var db = encodedMessage.AsSpan(0, outputByteCount - hashAlgorithm.HashLengthInBytes - 1);
        var h = encodedMessage.AsSpan(outputByteCount - hashAlgorithm.HashLengthInBytes - 1, hashAlgorithm.HashLengthInBytes);
        encodedMessage[^1] = 0xBC;

        // H = Hash(0x00 * 8 || messageDigest || salt). The eight zero bytes are the mgf-free
        // domain separator that makes PSS's proof go through.
        Span<byte> pad = stackalloc byte[8];
        pad.Clear();

        hashAlgorithm.AppendData(pad);
        hashAlgorithm.AppendData(digest);
        hashAlgorithm.AppendData(salt);
        hashAlgorithm.GetHashAndReset(h);

        // DB = PS(zeros) || 0x01 || salt
        db.Clear();
        db[^(salt.Length + 1)] = 0x01;
        salt.CopyTo(db[^salt.Length..]);

        // Clear top unused bits in DB BEFORE masking!
        db[0] &= (byte)(0xFF >> spareBits);

        // maskedDB = DB xor MGF1(H)
        MGF1.XorInto(mgfHashAlgorithm, h, db);

        // Zero the bits that outputBitLength does not cover. This is PSS's equivalent of
        // OAEP's leading 0x00 byte: it keeps EM, read big-endian, below the RSA modulus.
        db[0] &= (byte)(0xFF >> (8 * outputByteCount - outputBitLength));

        return encodedMessage;
    }

    #endregion

    #region Verification

    /// <summary>
    /// Checks a PSS encoded block against a message. Every failure - wrong length, bad
    /// trailer, non-zero spare bits, malformed DB, or mismatched H - returns <c>false</c>
    /// rather than throwing.
    /// </summary>
    /// <param name="data">The data the block should correspond to.</param>
    /// <param name="encodedData">The recovered encoded block.</param>
    /// <param name="outputBitLength">The bit length used when encoding.</param>
    /// <returns><see langword="true"> if the block is a valid PSS encoding of the message.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="outputBitLength"/> is not positive, or is too small for the padding.
    /// </exception>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> encodedData, int outputBitLength) {
        if (outputBitLength < 1)
            throw new ArgumentOutOfRangeException(nameof(outputBitLength), "Output bit length must be positive.");
        if (outputBitLength < (MinPaddingBytes * 8))
            throw new ArgumentOutOfRangeException(nameof(outputBitLength),
                "Output will not have enough room to write necessary padding.");

        // Check length and trailing bits
        var outputByteCount = (outputBitLength + 7) / 8;
        var spareBits = (8 * outputByteCount) - outputBitLength;
        if (encodedData.Length != outputByteCount) return false;
        if (encodedData[^1] != 0xBC) return false;
        if ((encodedData[0] & (byte)~(0xFF >> spareBits)) != 0) return false;

        // Pull apart the encoded message
        var db = encodedData[..(outputByteCount - hashAlgorithm.HashLengthInBytes - 1)].ToArray();
        var h = encodedData.Slice(outputByteCount - hashAlgorithm.HashLengthInBytes - 1, hashAlgorithm.HashLengthInBytes);

        // Unmask the DB
        MGF1.XorInto(mgfHashAlgorithm, h, db);

        // Clear the top spare bits created by MGF
        db[0] &= (byte)(0xFF >> spareBits);

        // 5. Verify DB padding (PS || 0x01 || salt). A fixed salt length is what
        // makes this arithmetic rather than a search: the separator
        // can only be in one place.
        var separator = db.Length - hashAlgorithm.HashLengthInBytes - 1;
        if (db[separator] != 0x01) return false;
        for (var i = 0; i < separator; i++)
            if (db[i] != 0x00) return false;
        var salt = db.AsSpan(separator + 1);

        // H = Hash(0x00 * 8 || messageDigest || salt)
        Span<byte> pad = stackalloc byte[8];
        pad.Clear();

        // Recompute the digest of the message.
        hashAlgorithm.AppendData(data);
        var digest = hashAlgorithm.GetHashAndReset();

        hashAlgorithm.AppendData(pad);
        hashAlgorithm.AppendData(digest);
        hashAlgorithm.AppendData(salt);
        var expectedH = hashAlgorithm.GetHashAndReset();

        return CryptographicOperations.FixedTimeEquals(expectedH, h);
    }

    #endregion

}
