using System.Numerics;
using MathUtils;
using Xunit;

namespace AsymmetricCryptography.Tests;

public class AsymmetricUtilsTests {
    // ==========================================
    // FromByteArray Tests
    // ==========================================

    [Fact]
    public void FromByteArray_ValidBigEndianBytes_ReturnsCorrectBigInteger() {
        // 0x01, 0x00 represents 256 in big-endian, unsigned format
        byte[] bytes = new byte[] { 0x01, 0x00 };

        BigInteger result = AsymmetricUtils.FromByteArray(bytes);

        Assert.Equal(256, result);
    }

    [Fact]
    public void FromByteArray_EmptySpan_ReturnsZero() {
        ReadOnlySpan<byte> bytes = ReadOnlySpan<byte>.Empty;

        BigInteger result = AsymmetricUtils.FromByteArray(bytes);

        Assert.Equal(BigInteger.Zero, result);
    }

    // ==========================================
    // GetRandom Tests
    // ==========================================

    [Fact]
    public void GetRandom_MinGreaterThanOrEqualToMax_ThrowsArgumentException() {
        BigInteger min = 10;
        BigInteger max = 5;

        Assert.Throws<ArgumentException>(() => AsymmetricUtils.GetRandom(min, max));
        Assert.Throws<ArgumentException>(() => AsymmetricUtils.GetRandom(10, 10));
    }

    [Theory]
    [InlineData(1, 10)]
    [InlineData(100, 105)]
    [InlineData(100000000000, 200000000000)]
    public void GetRandom_ValidRange_ReturnsValueWithinRange(long minVal, long maxVal) {
        BigInteger min = new BigInteger(minVal);
        BigInteger max = new BigInteger(maxVal);

        for (int i = 0; i < 50; i++) // Run multiple iterations to verify range consistency
        {
            BigInteger result = AsymmetricUtils.GetRandom(min, max);
            Assert.True(result >= min && result <= max, $"Result {result} was outside range [{min}, {max}]");
        }
    }

    // ==========================================
    // ToByteArray Tests
    // ==========================================

    [Fact]
    public void ToByteArray_NegativeValue_ThrowsInvalidOperationException() {
        BigInteger value = -5;

        Assert.Throws<InvalidOperationException>(() => AsymmetricUtils.ToByteArray(value, 4));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ToByteArray_InvalidByteCount_ThrowsArgumentOutOfRangeException(int byteCount) {
        BigInteger value = 10;

        Assert.Throws<ArgumentOutOfRangeException>(() => AsymmetricUtils.ToByteArray(value, byteCount));
    }

    [Fact]
    public void ToByteArray_ValueTooLargeForRequestedLength_ThrowsInvalidOperationException() {
        BigInteger value = 256; // Requires 2 bytes (0x01, 0x00)

        Assert.Throws<InvalidOperationException>(() => AsymmetricUtils.ToByteArray(value, 1));
    }

    [Fact]
    public void ToByteArray_ZeroValue_ReturnsArrayOfZeroes() {
        BigInteger value = BigInteger.Zero;
        int targetLength = 4;

        var result = AsymmetricUtils.ToByteArray(value, targetLength);

        Assert.Equal(targetLength, result.Length);
        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public void ToByteArray_ValidValue_PadsAndFormatsCorrectly() {
        BigInteger value = 256; // 0x01, 0x00
        int targetLength = 4;

        ReadOnlySpan<byte> result = AsymmetricUtils.ToByteArray(value, targetLength);

        byte[] expected = [0x00, 0x00, 0x01, 0x00];
        Assert.Equal(targetLength, result.Length);
        Assert.Equal(expected, result);
    }

    // ==========================================
    // GetRandomSafePrime Tests
    // ==========================================

    [Theory]
    [InlineData(4)]
    [InlineData(3)]
    [InlineData(0)]
    public void GetRandomSafePrime_BitLengthFourOrLess_ThrowsArgumentOutOfRangeException(int bitLength) {
        Assert.Throws<ArgumentOutOfRangeException>(() => AsymmetricUtils.GetRandomSafePrime(bitLength));
    }

    [Fact]
    public void GetRandomSafePrime_ValidBitLength_ReturnsValidSafeAndSophieGermainPrimes() {
        // Note: Make sure MathUtils.PrimeUtils implementation is available/mocked during runtime
        int bitLength = 8;

        var (p, q) = AsymmetricUtils.GetRandomSafePrime(bitLength);

        // Verify the relationship: p = 2q + 1
        Assert.Equal(p, (2 * q) + 1);

        // Verify prime conditions using PrimeUtils if accessible, or mathematical validation
        Assert.True(PrimeUtils.IsProbablePrime(p));
        Assert.True(PrimeUtils.IsProbablePrime(q));
    }
}