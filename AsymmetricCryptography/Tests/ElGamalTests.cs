using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace AsymmetricCryptography.Tests;

/// <summary>
/// Shared, expensive-to-generate state for <see cref="ElGamalTests"/>. Safe-prime group
/// generation is by far the most expensive setup step in this test suite, so it happens exactly
/// once per test class run via <see cref="IClassFixture{TFixture}"/> rather than once per test.
/// </summary>
public class ElGamalFixture {

    /// <summary>A key pair generated at the library's enforced minimum bit length.</summary>
    public ElGamal KeyPair { get; }

    /// <summary>A key pair generated to allow encryption of short messages.</summary>
    public ElGamal EncryptionKeyPair { get; }

    // /// <summary>
    // /// A full key pair generated at a size large enough that default SHA-256 OAEP has room for
    // /// real plaintext (the minimum bit length is far too small to fit OAEP's own overhead).
    // /// </summary>
    // public ElGamal KeyPair { get; }

    // /// <summary>A second, independent key pair, used for "wrong key" negative tests.</summary>
    // public ElGamal OtherKeyPair { get; }

    // /// <summary>A second key pair sharing <see cref="KeyPair"/>'s domain parameters.</summary>
    // public ElGamal SharedParametersKeyPair { get; }

    public byte[] Message { get; } = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public ElGamalFixture() {
        KeyPair = new ElGamal(ElGamal.MinimumBitLength);

        // Load known parameters and generate a key pair with them.
        // Done to avoid the time needed to generate large safe primes
        // with the inefficient algorithms we are using in this project.
        var oakleyGroup2Prime = @"00
            FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
            29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
            EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
            E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
            EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
            C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
            83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
            670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
            E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
            DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
            15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
                .Replace(" ", "").Replace("\r", "").Replace("\n", "").Trim();
        var p = BigInteger.Parse(oakleyGroup2Prime, NumberStyles.HexNumber);
        var q = (p - 1) >> 1;
        var g = 2;

        EncryptionKeyPair = new ElGamal(new ElGamal.Parameters(p, q, 2));
    }
}

public class ElGamalTests : IClassFixture<ElGamalFixture> {

    private readonly ElGamalFixture fixture;

    public ElGamalTests(ElGamalFixture fixture) => this.fixture = fixture;

    /// <summary>Byte length of a modulus, computed the same way the class under test does.</summary>
    private static int ByteCount(BigInteger p) => ((int)p.GetBitLength() + 7) / 8;

    #region Key generation / construction

    [Fact]
    public void Constructor_BitLengthBelowMinimum_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ElGamal(ElGamal.MinimumBitLength - 2));
    }

    [Fact]
    public void GeneratedModulus_HasRequestedBitLength() {
        Assert.Equal(ElGamal.MinimumBitLength, (int)fixture.KeyPair.GetParameters().P.GetBitLength());
    }

    [Fact]
    public void GeneratedParameters_SatisfySafePrimeRelationship() {
        var parameters = fixture.KeyPair.GetParameters();
        Assert.Equal(parameters.P, (parameters.Q * 2) + 1);
    }

    [Fact]
    public void Constructor_Parameters_ModulusTooSmall_Throws() {
        var bad = new ElGamal.Parameters(3, 1, 2); // P < 5
        Assert.Throws<ArgumentException>(() => new ElGamal(bad));
    }

    [Fact]
    public void Constructor_Parameters_SubgroupOrderMismatch_Throws() {
        var valid = fixture.KeyPair.GetParameters();
        var bad = valid with { Q = valid.Q + 2 }; // Q * 2 + 1 != P anymore
        Assert.Throws<ArgumentException>(() => new ElGamal(bad));
    }

    [Fact]
    public void Constructor_Parameters_GeneratorTooSmall_Throws() {
        var valid = fixture.KeyPair.GetParameters();
        var bad = valid with { G = 1 };
        Assert.Throws<ArgumentException>(() => new ElGamal(bad));
    }

    [Fact]
    public void Constructor_Parameters_GeneratorTooLarge_Throws() {
        var valid = fixture.KeyPair.GetParameters();
        var bad = valid with { G = valid.P - 1 };
        Assert.Throws<ArgumentException>(() => new ElGamal(bad));
    }

    [Fact]
    public void Constructor_Parameters_Valid_ProducesUsableKeyPair() {
        var signature = fixture.KeyPair.Sign(fixture.Message);
        Assert.True(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Constructor_PublicKey_HTooSmall_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        var bad = pub with { H = 1 };
        Assert.Throws<ArgumentOutOfRangeException>(() => new ElGamal(bad));
    }

    [Fact]
    public void Constructor_PublicKey_HTooLarge_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        var bad = pub with { H = pub.Parameters.P };
        Assert.Throws<ArgumentOutOfRangeException>(() => new ElGamal(bad));
    }

    [Fact]
    public void Constructor_PublicKey_NotInSubgroup_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        // p - 1 (i.e. -1 mod p) has order 2 in Z_p*. Since q is an odd prime, order-2 elements
        // are not in the order-q subgroup that public keys must belong to.
        var bad = pub with { H = pub.Parameters.P - 1 };
        Assert.Throws<ArgumentException>(() => new ElGamal(bad));
    }

    [Fact]
    public void PublicKeyOnly_CanEncryptAndVerify_CannotDecryptOrSign() {
        var publicOnly = new ElGamal(fixture.EncryptionKeyPair.GetPublicKey());
        var ciphertext = publicOnly.Encrypt(fixture.Message);
        var signature = fixture.EncryptionKeyPair.Sign(fixture.Message);

        Assert.True(publicOnly.Verify(fixture.Message, signature));
        Assert.Throws<InvalidOperationException>(() => publicOnly.Decrypt(ciphertext));
        Assert.Throws<InvalidOperationException>(() => publicOnly.Sign(fixture.Message));
        Assert.Throws<InvalidOperationException>(() => publicOnly.GetPrivateKey());

        // And the ciphertext really is decryptable by the holder of the private key.
        Assert.Equal(fixture.Message, fixture.EncryptionKeyPair.Decrypt(ciphertext));
    }

    [Fact]
    public void Constructor_KeyPair_Consistent_Succeeds() {
        var wrapped = new ElGamal(fixture.KeyPair.GetKeyPair());
        var signature = wrapped.Sign(fixture.Message);
        Assert.True(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Constructor_KeyPair_PrivateExponentTooSmall_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        var badPair = new ElGamal.KeyPair(pub, new ElGamal.PrivateKey(0, pub.Parameters));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ElGamal(badPair));
    }

    [Fact]
    public void Constructor_KeyPair_PrivateExponentTooLarge_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        var badPair = new ElGamal.KeyPair(pub, new ElGamal.PrivateKey(pub.Parameters.Q, pub.Parameters));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ElGamal(badPair));
    }

    [Fact]
    public void Constructor_KeyPair_MismatchedParameters_Throws() {
        var otherKeyPair = new ElGamal(fixture.KeyPair.GetParameters());

        var mismatched = new ElGamal.KeyPair(
            fixture.KeyPair.GetPublicKey(),
            otherKeyPair.GetPrivateKey());

        // Depending on how the two independently generated subgroup orders compare, the range
        // check or the parameters-equality check may fire first; either is a correct rejection.
        Assert.ThrowsAny<ArgumentException>(() => new ElGamal(mismatched));
    }

    [Fact]
    public void Constructor_KeyPair_InconsistentExponent_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        var wrongX = pub.Parameters.Q - 1; // in range, but (overwhelmingly likely) not the real secret
        var inconsistent = new ElGamal.KeyPair(pub, new ElGamal.PrivateKey(wrongX, pub.Parameters));

        Assert.Throws<ArgumentException>(() => new ElGamal(inconsistent));
    }

    #endregion

    #region Encrypt / Decrypt

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_ThenDecrypt_RoundTrips(string plaintext) {
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = fixture.EncryptionKeyPair.Encrypt(bytes);
        var decrypted = fixture.EncryptionKeyPair.Decrypt(ciphertext);

        Assert.Equal(bytes, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesTwiceModulusSizedCiphertext() {
        var expectedLength = 2 * ByteCount(fixture.EncryptionKeyPair.GetParameters().P);
        var ciphertext = fixture.EncryptionKeyPair.Encrypt(fixture.Message);
        Assert.Equal(expectedLength, ciphertext.Length);
    }

    [Fact]
    public void Encrypt_IsRandomized_AcrossCalls() {
        var c1 = fixture.EncryptionKeyPair.Encrypt(fixture.Message);
        var c2 = fixture.EncryptionKeyPair.Encrypt(fixture.Message);

        Assert.NotEqual(c1, c2); // A fresh ephemeral r is chosen every encryption
        Assert.Equal(fixture.Message, fixture.EncryptionKeyPair.Decrypt(c1));
        Assert.Equal(fixture.Message, fixture.EncryptionKeyPair.Decrypt(c2));
    }

    [Fact]
    public void Encrypt_MessageTooLongForModulus_Throws() {
        var byteCount = ByteCount(fixture.EncryptionKeyPair.GetParameters().P);
        var tooLong = new byte[byteCount]; // far beyond OAEP's capacity
        Assert.Throws<ArgumentException>(() => fixture.EncryptionKeyPair.Encrypt(tooLong));
    }

    [Fact]
    public void Decrypt_WrongLengthCiphertext_Throws() {
        Assert.Throws<ArgumentException>(() => fixture.EncryptionKeyPair.Decrypt(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Decrypt_CiphertextComponentNotLessThanModulus_Throws() {
        var byteCount = ByteCount(fixture.KeyPair.GetParameters().P);
        var oversized = new byte[2 * byteCount];
        Array.Fill(oversized, (byte)0xFF); // both components interpreted as >= p
        Assert.Throws<ArgumentException>(() => fixture.EncryptionKeyPair.Decrypt(oversized));
    }

    [Fact]
    public void Decrypt_NoPrivateKey_Throws() {
        var publicOnly = new ElGamal(fixture.KeyPair.GetPublicKey());
        var ciphertext = fixture.EncryptionKeyPair.Encrypt(fixture.Message);
        Assert.Throws<InvalidOperationException>(() => publicOnly.Decrypt(ciphertext));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws() {
        var ciphertext = fixture.EncryptionKeyPair.Encrypt(fixture.Message);
        ciphertext[^1] ^= 0xFF; // flips the low byte of c2

        // A tampered c2 recovers a bogus encoded message that fails OAEP's integrity check.
        Assert.ThrowsAny<Exception>(() => fixture.EncryptionKeyPair.Decrypt(ciphertext));
    }

    [Fact]
    public void EncryptDecrypt_WithExplicitSha1Encoder_RoundTrips() {
        var encoder = new OAEPEncoder(HashAlgorithmName.SHA1);
        var ciphertext = fixture.EncryptionKeyPair.Encrypt(fixture.Message, encoder);
        var decrypted = fixture.EncryptionKeyPair.Decrypt(ciphertext, encoder);

        Assert.Equal(fixture.Message, decrypted);
    }

    [Fact]
    public void Decrypt_WithMismatchedEncoder_Throws() {
        var ciphertext = fixture.EncryptionKeyPair.Encrypt(fixture.Message, new OAEPEncoder(HashAlgorithmName.SHA384));
        Assert.ThrowsAny<Exception>(() =>
            fixture.EncryptionKeyPair.Decrypt(ciphertext, new OAEPEncoder(HashAlgorithmName.SHA256)));
    }

    #endregion

    #region Sign / Verify

    [Fact]
    public void Sign_ThenVerify_Succeeds() {
        var signature = fixture.KeyPair.Sign(fixture.Message);
        Assert.True(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Sign_ProducesTwiceModulusSizedSignature() {
        var expectedLength = 2 * ByteCount(fixture.KeyPair.GetParameters().P);
        var signature = fixture.KeyPair.Sign(fixture.Message);
        Assert.Equal(expectedLength, signature.Length);
    }

    [Fact]
    public void Sign_IsRandomized_AcrossCalls() {
        var s1 = fixture.KeyPair.Sign(fixture.Message);
        var s2 = fixture.KeyPair.Sign(fixture.Message);

        Assert.NotEqual(s1, s2); // A fresh ephemeral k is chosen every signature
        Assert.True(fixture.KeyPair.Verify(fixture.Message, s1));
        Assert.True(fixture.KeyPair.Verify(fixture.Message, s2));
    }

    [Fact]
    public void Verify_TamperedMessage_ReturnsFalse() {
        var signature = fixture.KeyPair.Sign(fixture.Message);
        var tampered = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dot");

        Assert.False(fixture.KeyPair.Verify(tampered, signature));
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalseOrThrows() {
        var signature = fixture.KeyPair.Sign(fixture.Message);
        signature[^1] ^= 0xFF; // flips the low byte of s

        // A flipped bit either yields a component >= p (Verify rejects with an exception) or a
        // well-formed but incorrect component (Verify rejects by returning false). Either
        // outcome means the tampering was caught.
        try {
            Assert.False(fixture.KeyPair.Verify(fixture.Message, signature));
        } catch (ArgumentException) {
            // Also an acceptable rejection.
        }
    }

    [Fact]
    public void Verify_WrongLengthSignature_ReturnsFalse() {
        Assert.False(fixture.KeyPair.Verify(fixture.Message, new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Verify_SignedByDifferentKey_ReturnsFalse() {
        var otherKeyPair = new ElGamal(fixture.KeyPair.GetParameters());
        var signature = otherKeyPair.Sign(fixture.Message);
        Assert.False(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Verify_SignatureComponentNotLessThanModulus_Throws() {
        var byteCount = ByteCount(fixture.KeyPair.GetParameters().P);
        var oversized = new byte[2 * byteCount];
        Array.Fill(oversized, (byte)0xFF); // both components interpreted as >= p
        Assert.Throws<ArgumentException>(() => fixture.KeyPair.Verify(fixture.Message, oversized));
    }

    [Fact]
    public void Sign_NoPrivateKey_Throws() {
        var publicOnly = new ElGamal(fixture.KeyPair.GetPublicKey());
        Assert.Throws<InvalidOperationException>(() => publicOnly.Sign(fixture.Message));
    }

    [Fact]
    public void SignAndVerify_WithMismatchedHashAlgorithms_Fails() {
        var signature = fixture.KeyPair.Sign(fixture.Message, HashAlgorithmName.SHA384);
        Assert.False(fixture.KeyPair.Verify(fixture.Message, signature, HashAlgorithmName.SHA256));
        Assert.True(fixture.KeyPair.Verify(fixture.Message, signature, HashAlgorithmName.SHA384));
    }

    #endregion

}
