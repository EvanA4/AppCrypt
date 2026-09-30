using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace AsymmetricCryptography.Tests;

/// <summary>
/// Shared, expensive-to-generate state for <see cref="RSATests"/>. RSA key generation at the
/// library's enforced minimum (1024-bit) modulus is by far the most expensive setup step in this
/// test suite, so it happens exactly once per test class run via <see cref="IClassFixture{TFixture}"/>
/// rather than once per test.
/// </summary>
public class RSAFixture {

    /// <summary>A full key pair, generated once with a random public exponent.</summary>
    public RSA KeyPair { get; }

    /// <summary>A second, independent key pair, used for "wrong key" negative tests.</summary>
    public RSA OtherKeyPair { get; }

    /// <summary>A key pair generated with the fixed public exponent 65537 (0x10001).</summary>
    public RSA FixedExponentKeyPair { get; }

    public byte[] Message { get; } = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public RSAFixture() {
        KeyPair = new RSA(RSA.MinimumBitLength);
        OtherKeyPair = new RSA(RSA.MinimumBitLength);
        FixedExponentKeyPair = new RSA(RSA.MinimumBitLength, 65537);
    }
}

public class RSATests : IClassFixture<RSAFixture> {

    private readonly RSAFixture fixture;

    public RSATests(RSAFixture fixture) => this.fixture = fixture;

    #region Key generation / construction

    [Fact]
    public void Constructor_BitLengthBelowMinimum_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RSA(RSA.MinimumBitLength - 2));
    }

    [Fact]
    public void Constructor_OddBitLength_Throws() {
        Assert.Throws<ArgumentException>(() => new RSA(RSA.MinimumBitLength + 1));
    }

    [Fact]
    public void Constructor_FixedExponent_EvenExponent_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RSA(RSA.MinimumBitLength, 4));
    }

    [Fact]
    public void Constructor_FixedExponent_TooSmall_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RSA(RSA.MinimumBitLength, 1));
    }

    [Fact]
    public void Constructor_FixedExponent_ProducesMatchingPublicExponent() {
        Assert.Equal(new BigInteger(65537), fixture.FixedExponentKeyPair.GetPublicKey().Exponent);
    }

    [Fact]
    public void GeneratedModulus_HasRequestedBitLength() {
        Assert.Equal(RSA.MinimumBitLength, (int)fixture.KeyPair.GetPublicKey().Parameters.Modulus.GetBitLength());
    }

    [Fact]
    public void Constructor_PublicKey_EvenModulus_Throws() {
        var badModulus = new RSA.PublicKey(65537, new RSA.Parameters(1024)); // even
        Assert.Throws<ArgumentOutOfRangeException>(() => new RSA(badModulus));
    }

    [Fact]
    public void Constructor_PublicKey_ModulusTooSmall_Throws() {
        var small = new RSA.PublicKey(65537, new RSA.Parameters(1023)); // odd but tiny
        Assert.Throws<ArgumentOutOfRangeException>(() => new RSA(small));
    }

    [Fact]
    public void Constructor_PublicKey_EvenExponent_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        var badExponent = new RSA.PublicKey(pub.Exponent + 1, pub.Parameters); // shift to even
        Assert.Throws<ArgumentOutOfRangeException>(() => new RSA(badExponent));
    }

    [Fact]
    public void Constructor_PublicKey_ExponentTooLarge_Throws() {
        var pub = fixture.KeyPair.GetPublicKey();
        var badExponent = new RSA.PublicKey(pub.Parameters.Modulus + 1, pub.Parameters);
        Assert.Throws<ArgumentOutOfRangeException>(() => new RSA(badExponent));
    }

    [Fact]
    public void PublicKeyOnly_CanEncryptAndVerify_CannotDecryptOrSign() {
        var publicOnly = new RSA(fixture.KeyPair.GetPublicKey());
        var ciphertext = publicOnly.Encrypt(fixture.Message);
        var signature = fixture.KeyPair.Sign(fixture.Message);

        Assert.True(publicOnly.Verify(fixture.Message, signature));
        Assert.Throws<InvalidOperationException>(() => publicOnly.Decrypt(ciphertext));
        Assert.Throws<InvalidOperationException>(() => publicOnly.Sign(fixture.Message));
        Assert.Throws<InvalidOperationException>(() => publicOnly.GetPrivateKey());

        // And the ciphertext really is decryptable by the holder of the private key.
        Assert.Equal(fixture.Message, fixture.KeyPair.Decrypt(ciphertext));
    }

    [Fact]
    public void Constructor_KeyPair_Consistent_Succeeds() {
        var wrapped = new RSA(fixture.KeyPair.GetKeyPair());
        var signature = wrapped.Sign(fixture.Message);
        Assert.True(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Constructor_KeyPair_MismatchedModulus_Throws() {
        var mismatched = new RSA.KeyPair(
            fixture.KeyPair.GetPublicKey(),
            fixture.OtherKeyPair.GetPrivateKey());

        Assert.Throws<ArgumentException>(() => new RSA(mismatched));
    }

    [Fact]
    public void Constructor_KeyPair_InconsistentExponents_Throws() {
        var n = fixture.KeyPair.GetPublicKey().Parameters;
        var inconsistent = new RSA.KeyPair(
            fixture.KeyPair.GetPublicKey(),
            new RSA.PrivateKey(fixture.OtherKeyPair.GetPrivateKey().Exponent, n));

        Assert.ThrowsAny<ArgumentException>(() => new RSA(inconsistent));
    }

    #endregion

    #region Encrypt / Decrypt

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void Encrypt_ThenDecrypt_RoundTrips(string plaintext) {
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = fixture.KeyPair.Encrypt(bytes);
        var decrypted = fixture.KeyPair.Decrypt(ciphertext);

        Assert.Equal(bytes, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesModulusSizedCiphertext() {
        var ciphertext = fixture.KeyPair.Encrypt(fixture.Message);
        Assert.Equal(RSA.MinimumBitLength / 8, ciphertext.Length);
    }

    [Fact]
    public void Encrypt_IsRandomized_AcrossCalls() {
        var c1 = fixture.KeyPair.Encrypt(fixture.Message);
        var c2 = fixture.KeyPair.Encrypt(fixture.Message);

        Assert.NotEqual(c1, c2); // OAEP salts every encryption
        Assert.Equal(fixture.Message, fixture.KeyPair.Decrypt(c1));
        Assert.Equal(fixture.Message, fixture.KeyPair.Decrypt(c2));
    }

    [Fact]
    public void Encrypt_MessageTooLongForModulus_Throws() {
        var tooLong = new byte[RSA.MinimumBitLength / 8]; // far beyond OAEP's capacity
        Assert.Throws<ArgumentException>(() => fixture.KeyPair.Encrypt(tooLong));
    }

    [Fact]
    public void Decrypt_WrongLengthCiphertext_Throws() {
        Assert.Throws<ArgumentException>(() => fixture.KeyPair.Decrypt(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Decrypt_CiphertextNotLessThanModulus_Throws() {
        var oversized = new byte[RSA.MinimumBitLength / 8];
        Array.Fill(oversized, (byte)0xFF); // interpreted value exceeds any modulus of this bit length
        Assert.Throws<ArgumentException>(() => fixture.KeyPair.Decrypt(oversized));
    }

    [Fact]
    public void Decrypt_NoPrivateKey_Throws() {
        var publicOnly = new RSA(fixture.KeyPair.GetPublicKey());
        var ciphertext = fixture.KeyPair.Encrypt(fixture.Message);
        Assert.Throws<InvalidOperationException>(() => publicOnly.Decrypt(ciphertext));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsOrFailsPadding() {
        var ciphertext = fixture.KeyPair.Encrypt(fixture.Message);
        ciphertext[^1] ^= 0xFF;

        // A tampered OAEP block should fail padding validation, not silently return garbage.
        Assert.ThrowsAny<Exception>(() => fixture.KeyPair.Decrypt(ciphertext));
    }

    [Fact]
    public void EncryptDecrypt_WithExplicitSha1Encoder_RoundTrips() {
        var encoder = new OAEPEncoder(HashAlgorithmName.SHA1);
        var ciphertext = fixture.KeyPair.Encrypt(fixture.Message, encoder);
        var decrypted = fixture.KeyPair.Decrypt(ciphertext, encoder);

        Assert.Equal(fixture.Message, decrypted);
    }

    #endregion

    #region Sign / Verify

    [Fact]
    public void Sign_ThenVerify_Succeeds() {
        var signature = fixture.KeyPair.Sign(fixture.Message);
        Assert.True(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Sign_ProducesModulusSizedSignature() {
        var signature = fixture.KeyPair.Sign(fixture.Message);
        Assert.Equal(RSA.MinimumBitLength / 8, signature.Length);
    }

    [Fact]
    public void Sign_IsRandomized_AcrossCalls() {
        var s1 = fixture.KeyPair.Sign(fixture.Message);
        var s2 = fixture.KeyPair.Sign(fixture.Message);

        Assert.NotEqual(s1, s2); // PSS salts every signature
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
    public void Verify_TamperedSignature_ReturnsFalse() {
        var signature = fixture.KeyPair.Sign(fixture.Message);
        signature[0] ^= 0xFF;

        Assert.False(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Verify_WrongLengthSignature_ReturnsFalse() {
        Assert.False(fixture.KeyPair.Verify(fixture.Message, new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Verify_SignedByDifferentKey_ReturnsFalse() {
        var signature = fixture.OtherKeyPair.Sign(fixture.Message);
        Assert.False(fixture.KeyPair.Verify(fixture.Message, signature));
    }

    [Fact]
    public void Sign_NoPrivateKey_Throws() {
        var publicOnly = new RSA(fixture.KeyPair.GetPublicKey());
        Assert.Throws<InvalidOperationException>(() => publicOnly.Sign(fixture.Message));
    }

    [Fact]
    public void SignAndVerify_WithMismatchedEncoders_Fails() {
        var signature = fixture.KeyPair.Sign(fixture.Message, new PSSEncoder(HashAlgorithmName.SHA384));
        Assert.False(fixture.KeyPair.Verify(fixture.Message, signature, new PSSEncoder(HashAlgorithmName.SHA256)));
        Assert.True(fixture.KeyPair.Verify(fixture.Message, signature, new PSSEncoder(HashAlgorithmName.SHA384)));
    }

    #endregion

}
