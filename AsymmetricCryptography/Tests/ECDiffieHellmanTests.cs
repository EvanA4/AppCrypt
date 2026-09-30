using System.Security.Cryptography;
using Xunit;

using ECCurve = MathUtils.ECCurve;
using ECPoint = MathUtils.ECPoint;
using Parameters = AsymmetricCryptography.ECParameters.Parameters;

namespace AsymmetricCryptography.Tests;

/// <summary>
/// Shared, cached state for <see cref="ECDiffieHellmanTests"/>: a small toy curve (chosen so that
/// the whole test class stays fast) plus the derived key pairs and test vectors, all computed
/// once via <see cref="IClassFixture{TFixture}"/>.
/// </summary>
public class ECDiffieHellmanFixture {

    #region Toy curve fixture

    // y^2 = x^3 + 2x + 3 (mod 83). #E(F_83) = 86 = 2 * 43, so this curve has a cofactor of 2 and a
    // prime-order-43 subgroup -- structurally analogous to the safe-prime groups DiffieHellman.cs
    // uses, which lets the "wrong subgroup" validation path be exercised meaningfully (a curve of
    // prime order wouldn't have any non-identity point of the "wrong" order to test with).
    public static readonly ECCurve Curve = new(2, 3, 83);

    /// <summary>A generator of the order-43 subgroup.</summary>
    public static readonly ECPoint Generator = Curve.GetPoint(28, 4);

    public const int Order = 43;

    /// <summary>A point of the full order-86 group that is NOT in the order-43 subgroup.</summary>
    public static readonly ECPoint WrongOrderPoint = Curve.GetPoint(4, 18);

    /// <summary>Coordinates that satisfy neither y^2 = x^3 + 2x + 3 mod 83.</summary>
    public static readonly ECPoint NotOnCurvePoint = default;

    #endregion

    public Parameters Parameters { get; } = new(Curve, Generator, Order);

    public ECDiffieHellman Alice { get; }
    public ECDiffieHellman Bob { get; }

    public ECDiffieHellmanFixture() {
        Alice = new ECDiffieHellman(Parameters);
        Bob = new ECDiffieHellman(Parameters);
    }
}

public class ECDiffieHellmanTests : IClassFixture<ECDiffieHellmanFixture> {

    private readonly ECDiffieHellmanFixture fixture;

    public ECDiffieHellmanTests(ECDiffieHellmanFixture fixture) => this.fixture = fixture;

    #region Parameter validation

    [Fact]
    public void Constructor_FieldTooSmall_Throws() {
        // A valid (non-singular) curve, but with P < 5.
        var tinyField = new Parameters(new ECCurve(1, 1, 3), ECDiffieHellmanFixture.Generator, ECDiffieHellmanFixture.Order);
        Assert.Throws<ArgumentException>(() => new ECDiffieHellman(tinyField));
    }

    [Fact]
    public void Constructor_GeneratorAtInfinity_Throws() {
        var bad = new Parameters(ECDiffieHellmanFixture.Curve, ECPoint.PointAtInfinity, ECDiffieHellmanFixture.Order);
        Assert.Throws<ArgumentException>(() => new ECDiffieHellman(bad));
    }

    [Fact]
    public void Constructor_GeneratorNotOnCurve_Throws() {
        var bad = new Parameters(ECDiffieHellmanFixture.Curve, ECDiffieHellmanFixture.NotOnCurvePoint, ECDiffieHellmanFixture.Order);
        Assert.Throws<ArgumentException>(() => new ECDiffieHellman(bad));
    }

    [Fact]
    public void Constructor_OrderTooSmall_Throws() {
        var bad = new Parameters(ECDiffieHellmanFixture.Curve, ECDiffieHellmanFixture.Generator, 1);
        Assert.Throws<ArgumentException>(() => new ECDiffieHellman(bad));
    }

    [Fact]
    public void Constructor_GeneratorDoesNotHaveStatedOrder_Throws() {
        // The generator's true order is 43; claiming an order of 2 is inconsistent.
        var bad = new Parameters(ECDiffieHellmanFixture.Curve, ECDiffieHellmanFixture.Generator, 2);
        Assert.Throws<ArgumentException>(() => new ECDiffieHellman(bad));
    }

    #endregion

    #region Key generation

    [Fact]
    public void Constructor_ValidParameters_ProducesPublicKeyInSubgroup() {
        var publicKey = fixture.Alice.GetPublicValue();
        Assert.NotEqual(ECPoint.PointAtInfinity, publicKey);
        Assert.Equal(ECPoint.PointAtInfinity, ECDiffieHellmanFixture.Order * publicKey);
    }

    [Fact]
    public void GetParameters_ReturnsParametersUsedToConstruct() {
        Assert.Equal(fixture.Parameters, fixture.Alice.GetParameters());
    }

    #endregion

    #region Key agreement

    [Fact]
    public void ComputeSharedPoint_BothParties_AgreeOnSamePoint() {
        var aliceShared = fixture.Alice.ComputeSharedPoint(fixture.Bob.GetPublicValue());
        var bobShared = fixture.Bob.ComputeSharedPoint(fixture.Alice.GetPublicValue());

        Assert.Equal(aliceShared, bobShared);
    }

    [Fact]
    public void ComputeSharedKey_BothParties_AgreeOnSameBytes() {
        var aliceKey = fixture.Alice.ComputeSharedKey(fixture.Bob.GetPublicValue(), 32);
        var bobKey = fixture.Bob.ComputeSharedKey(fixture.Alice.GetPublicValue(), 32);

        Assert.Equal(aliceKey, bobKey);
    }

    [Fact]
    public void ComputeSharedKey_ZeroOrNegativeByteCount_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Alice.ComputeSharedKey(fixture.Bob.GetPublicValue(), 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Alice.ComputeSharedKey(fixture.Bob.GetPublicValue(), -5));
    }

    /// <summary>
    /// Cross-checks the key-derivation step against .NET's own HKDF implementation, mirroring the
    /// implementation's documented use of HKDF-SHA512 over the shared point's X coordinate.
    /// </summary>
    [Fact]
    public void ComputeSharedKey_MatchesIndependentHkdfComputation() {
        var actual = fixture.Alice.ComputeSharedKey(fixture.Bob.GetPublicValue(), 32);

        var rawShared = fixture.Bob.ComputeSharedPoint(fixture.Alice.GetPublicValue());
        var byteLength = ((int)ECDiffieHellmanFixture.Curve.P.GetBitLength() + 7) / 8;
        var rawSharedBytes = rawShared.X.ToByteArray(isUnsigned: true, isBigEndian: true);

        // Left-pad to the same fixed length the implementation uses.
        if (rawSharedBytes.Length < byteLength) {
            var padded = new byte[byteLength];
            Array.Copy(rawSharedBytes, 0, padded, byteLength - rawSharedBytes.Length, rawSharedBytes.Length);
            rawSharedBytes = padded;
        }

        var expected = HKDF.DeriveKey(HashAlgorithmName.SHA512, rawSharedBytes, 32);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ComputeSharedPoint_PointAtInfinity_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Alice.ComputeSharedPoint(ECPoint.PointAtInfinity));
    }

    [Fact]
    public void ComputeSharedPoint_PointNotOnCurve_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => fixture.Alice.ComputeSharedPoint(ECDiffieHellmanFixture.NotOnCurvePoint));
    }

    [Fact]
    public void ComputeSharedPoint_WrongOrderPoint_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => fixture.Alice.ComputeSharedPoint(ECDiffieHellmanFixture.WrongOrderPoint));
    }

    #endregion
}
