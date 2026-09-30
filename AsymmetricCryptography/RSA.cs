using System.Net.Mail;
using System.Numerics;
using System.Security.Cryptography;
using MathUtils;

namespace AsymmetricCryptography;

/// <summary>
/// Implementation of RSA.
/// </summary>
public class RSA {

    #region Record types

    /// <summary>
    /// RSA group parameters.
    /// </summary>
    /// <param name="Modulus">The modulus for group operations.</param>
    public record struct Parameters(BigInteger Modulus);

    /// <summary>
    /// RSA public key.
    /// </summary>
    /// <param name="Exponent">The public exponent.</param>
    /// <param name="Parameters">The group parameters.</param>
    public sealed record PublicKey(BigInteger Exponent, Parameters Parameters);

    /// <summary>
    /// RSA public key.
    /// </summary>
    /// <param name="Exponent">The private exponent.</param>
    /// <param name="Parameters">The group parameters.</param>
    public sealed record PrivateKey(BigInteger Exponent, Parameters Parameters);

    /// <summary>
    /// A RSA key pair.
    /// </summary>
    /// <param name="PublicKey">The public key.</param>
    /// <param name="PrivateKey">The private key.</param>
    public record struct KeyPair(PublicKey PublicKey, PrivateKey PrivateKey);

    #endregion

    #region Configuration

    /// <summary>
    /// The smallest modulus size, in bits, this implementation will generate or accept.
    /// </summary>
    public const int MinimumBitLength = 1024;

    private PublicKey PUK = null;
    private PrivateKey PRK = null;
    private KeyPair KP;

    #endregion

    #region Key retrieval

    /// <summary>Returns the public key held by this instance.</summary>
    public PublicKey GetPublicKey() => PUK;

    /// <summary>Returns the private key held by this instance.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance was constructed from a public key only.
    /// </exception>
    public PrivateKey GetPrivateKey() {
        if (PRK == null) throw new InvalidOperationException();
        return PRK;
    }

    /// <summary>Returns the public/private key pair.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance was constructed from a public key only.
    /// </exception>
    public KeyPair GetKeyPair() {
        if (PRK == null) throw new InvalidOperationException();
        return KP;
    }

    #endregion

    #region Constructors

    /// <summary>
    /// Create an RSA instance. Generates parameters and key pair.
    /// </summary>
    /// <param name="bitLength">Modulus size in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="bitLength"/> is below <see cref="MinimumBitLength"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="bitLength"/> is odd.</exception>
    public RSA(int bitLength) {
        if (bitLength < MinimumBitLength) throw new ArgumentOutOfRangeException();
        if ((bitLength & 1) != 0) throw new ArgumentException();

        while (true)
        {
            BigInteger cP = PrimeUtils.GetRandomPrime(bitLength >> 1);
            BigInteger cQ = PrimeUtils.GetRandomPrime(bitLength >> 1);
            BigInteger cN = cP * cQ;
            if ((cN & (BigInteger.One << (bitLength - 1))) == BigInteger.Zero) continue;

            BigInteger lN = (cP - 1) * (cQ - 1) / BigInteger.GreatestCommonDivisor(cP - 1, cQ - 1);
            BigInteger e = 65537;
            if (BigInteger.GreatestCommonDivisor(e, lN) != BigInteger.One) continue;
            
            BigInteger d = e.ModInverse(lN);
            if (d < (BigInteger.One << (bitLength / 3 - 1))) continue;

            // solution was found
            Parameters parameters = new Parameters(cN);
            PUK = new PublicKey(e, parameters);
            PRK = new PrivateKey(d, parameters);
            KP = new KeyPair(PUK, PRK);
            break;
        }
    }

    /// <summary>
    /// Create an RSA instance. Generates parameters and key pair for a fixed e value.
    /// </summary>
    /// <param name="bitLength">Modulus size in bits.</param>
    /// <param name="publicExponent">A fixed public exponent.</param>
    public RSA(int bitLength, BigInteger publicExponent) {
        if (bitLength < MinimumBitLength) throw new ArgumentOutOfRangeException();
        if ((bitLength & 1) != 0) throw new ArgumentException();
        if ((publicExponent & 1) == 0) throw new ArgumentOutOfRangeException();
        if (publicExponent < 3) throw new ArgumentOutOfRangeException();

        while (true)
        {
            BigInteger cP = PrimeUtils.GetRandomPrime(bitLength >> 1);
            BigInteger cQ = PrimeUtils.GetRandomPrime(bitLength >> 1);
            BigInteger cN = cP * cQ;
            if ((cN & (BigInteger.One << (bitLength - 1))) == BigInteger.Zero) continue;

            BigInteger lN = (cP - 1) * (cQ - 1) / BigInteger.GreatestCommonDivisor(cP - 1, cQ - 1);
            BigInteger e = publicExponent;
            if (BigInteger.GreatestCommonDivisor(e, lN) != BigInteger.One) continue;
            
            BigInteger d = e.ModInverse(lN);
            if (d < (BigInteger.One << (bitLength / 3 - 1))) continue;

            // solution was found
            Parameters parameters = new Parameters(cN);
            PUK = new PublicKey(e, parameters);
            PRK = new PrivateKey(d, parameters);
            KP = new KeyPair(PUK, PRK);
            break;
        }
    }

    /// <summary>
    /// Wraps an existing public key. The resulting instance can encrypt and verify but not
    /// decrypt or sign.
    /// </summary>
    /// <param name="publicKey">The public key to use.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The modulus is not a positive odd integer of at least <see cref="MinimumBitLength"/> bits,
    /// or the exponent is not odd and in <c>[3, n)</c>.
    /// </exception>
    public RSA(PublicKey publicKey) {
        if (publicKey.Parameters.Modulus < MinimumBitLength) throw new ArgumentOutOfRangeException();
        if ((publicKey.Parameters.Modulus & 1) == 0) throw new ArgumentOutOfRangeException();
        if ((publicKey.Exponent & 1) == 0) throw new ArgumentOutOfRangeException();
        if (publicKey.Exponent > publicKey.Parameters.Modulus) throw new ArgumentOutOfRangeException();
        PUK = publicKey;
    }

    /// <summary>
    /// Wraps an existing key pair.
    /// </summary>
    /// <param name="keyPair">The key pair to adopt.</param>
    /// <exception cref="ArgumentOutOfRangeException">The private exponent is outside <c>[1, n)</c>, or the public half is malformed.</exception>
    /// <exception cref="ArgumentException">The private key does not match the public key.</exception>
    public RSA(KeyPair keyPair) : this(keyPair.PublicKey) {
        if (keyPair.PublicKey.Parameters.Modulus < MinimumBitLength) throw new ArgumentOutOfRangeException();
        if ((keyPair.PublicKey.Parameters.Modulus & 1) == 0) throw new ArgumentOutOfRangeException();
        if ((keyPair.PublicKey.Exponent & 1) == 0) throw new ArgumentOutOfRangeException();
        if (keyPair.PublicKey.Exponent > keyPair.PublicKey.Parameters.Modulus) throw new ArgumentOutOfRangeException();
        if (keyPair.PublicKey.Parameters.Modulus != keyPair.PrivateKey.Parameters.Modulus) throw new ArgumentException();

        BigInteger m = BigInteger.GetRandom(BigInteger.Zero, keyPair.PublicKey.Parameters.Modulus - BigInteger.One);
        BigInteger c = m.ModExp(keyPair.PublicKey.Exponent, keyPair.PublicKey.Parameters.Modulus);
        BigInteger m2 = c.ModExp(keyPair.PrivateKey.Exponent, keyPair.PublicKey.Parameters.Modulus);
        if (m != m2) throw new ArgumentException();

        PUK = keyPair.PublicKey;
        PRK = keyPair.PrivateKey;
        KP = keyPair;
    }

    #endregion

    #region Encryption operations

    /// <summary>
    /// Encrypts a message using OAEP with SHA-256 and an empty label.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <returns>A ciphertext <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="ArgumentException">The plaintext is too long for the modulus.</exception>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext) => Encrypt(plaintext, new OAEPEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Encrypts a message using a caller-supplied OAEP encoder.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="encoder">The OAEP encoder supplying the hash, MGF1 hash, and label.</param>
    /// <returns>A ciphertext <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="ArgumentException">The plaintext exceeds the encoder's capacity for this modulus.</exception>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, OAEPEncoder encoder) {
        int modulusBytes = (int) (PUK.Parameters.Modulus.GetBitLength() + 7) >> 3;
        if (plaintext.Length > encoder.GetMaxMessageLength(modulusBytes)) throw new ArgumentException();
        BigInteger encodedNum = new BigInteger(encoder.Encode(plaintext, modulusBytes), isUnsigned: true, isBigEndian: true);
        BigInteger cipherNum = encodedNum.ModExp(PUK.Exponent, PUK.Parameters.Modulus);
        return ZeroPaddedBigEndianByteArray(cipherNum, modulusBytes);
    }

    /// <summary>
    /// Decrypts a ciphertext produced with OAEP using SHA-256 and an empty label.
    /// </summary>
    /// <param name="ciphertext">The ciphertext, which must be <see cref="ModulusByteCount"/> bytes.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="InvalidOperationException">No private key is held.</exception>
    /// <exception cref="ArgumentException">The ciphertext is the wrong length, too large, or fails OAEP checks.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext) => Decrypt(ciphertext, new OAEPEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Decrypts a ciphertext using a caller-supplied OAEP encoder.
    /// </summary>
    /// <param name="ciphertext">The ciphertext, which must be <see cref="ModulusByteCount"/> bytes.</param>
    /// <param name="encoder">An encoder configured identically to the one used to encrypt.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="InvalidOperationException">No private key is held.</exception>
    /// <exception cref="ArgumentException">The ciphertext is the wrong length, too large, or fails OAEP checks.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, OAEPEncoder encoder) {
        if (PRK == null) throw new InvalidOperationException();
        int modulusBytes = (int) (PUK.Parameters.Modulus.GetBitLength() + 7) >> 3;
        if (ciphertext.Length != modulusBytes) throw new ArgumentException();
        BigInteger cipherNum = new BigInteger(ciphertext, isUnsigned: true, isBigEndian: true);
        if (cipherNum >= PUK.Parameters.Modulus) throw new ArgumentException();
        BigInteger plainTextNum = cipherNum.ModExp(PRK.Exponent, PRK.Parameters.Modulus);
        return encoder.Decode(ZeroPaddedBigEndianByteArray(plainTextNum, modulusBytes));
    }

    #endregion

    #region Signing operations

    /// <summary>
    /// Signs data using PSS with SHA-256.
    /// </summary>
    /// <param name="data">The data to sign; it is hashed internally.</param>
    /// <returns>A signature <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="InvalidOperationException">No private key is available.</exception>
    public byte[] Sign(ReadOnlySpan<byte> data) => Sign(data, new PSSEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Signs data using a caller-supplied PSS encoder. Because PSS salts every signature,
    /// signing the same data twice yields different signatures.
    /// </summary>
    /// <param name="data">The data to sign; it is hashed internally.</param>
    /// <param name="pss">The PSS encoder supplying the hash and MGF1 hash.</param>
    /// <returns>A signature <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="InvalidOperationException">No private key is held, or the modulus is too small for this encoder.</exception>
    public byte[] Sign(ReadOnlySpan<byte> data, PSSEncoder pss) {
        if (PRK == null) throw new InvalidOperationException();
        int signBits = (int) PUK.Parameters.Modulus.GetBitLength() - 1;
        int modulusBytes = (int) (PUK.Parameters.Modulus.GetBitLength() + new BigInteger(7)) >> 3;
        BigInteger plainTextNum = new BigInteger(pss.Encode(data, signBits), isUnsigned: true, isBigEndian: true);
        return ZeroPaddedBigEndianByteArray(plainTextNum.ModExp(PRK.Exponent, PRK.Parameters.Modulus), modulusBytes);
    }

    /// <summary>
    /// Verifies a PSS signature using SHA-256.
    /// </summary>
    /// <param name="data">The data that was supposedly signed.</param>
    /// <param name="signature">The signature to check.</param>
    /// <returns><see langword="true"> if the signature is valid for this key.</returns>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => Verify(data, signature, new PSSEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Verifies a PSS signature using a caller-supplied PSS encoder. Malformed input is reported
    /// as <c>false</c> rather than thrown, so callers need only one failure path.
    /// </summary>
    /// <param name="data">The data that was supposedly signed.</param>
    /// <param name="signature">The signature to check.</param>
    /// <param name="pss">An encoder configured identically to the one used to sign.</param>
    /// <returns><see langword="true"> if the signature is valid for this key.</returns>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, PSSEncoder pss) {
        int modulusBytes = (int) (PUK.Parameters.Modulus.GetBitLength() + 7) >> 3;
        int signBits = (int) PUK.Parameters.Modulus.GetBitLength() - 1;
        int signBytes = (int) (PUK.Parameters.Modulus.GetBitLength() + 6) / 8;
        if (signature.Length != modulusBytes) return false;
        BigInteger signNum = new BigInteger(signature, isUnsigned: true, isBigEndian: true).ModExp(PUK.Exponent, PUK.Parameters.Modulus);
        return pss.Verify(data, ZeroPaddedBigEndianByteArray(signNum, signBytes), signBits);
    }

    #endregion

    private byte[] ZeroPaddedBigEndianByteArray(BigInteger num, int length)
    {
        byte[] noPadding = num.ToByteArray(isBigEndian: true, isUnsigned: true);
        if (noPadding.Length > length) throw new ArgumentException();
        byte[] output = new byte[length];
        for (int i = 0; i < noPadding.Length; ++i) output[length - noPadding.Length + i] = noPadding[i];
        return output;
    }

}
