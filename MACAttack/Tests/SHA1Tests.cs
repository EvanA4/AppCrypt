using System.Text;
using Xunit;

namespace MACAttack.Tests;

public class SHA1Tests {

    [Theory]
    [InlineData("", "da39a3ee5e6b4b0d3255bfef95601890afd80709")]
    [InlineData("abc", "a9993e364706816aba3e25717850c26c9cd0d89d")]
    [InlineData(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1")]
    [InlineData("The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")]
    [InlineData("The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")]
    public void ComputeHash_MatchesKnownTestVectors(string asciiInput, string expectedHex) {
        var message = Encoding.ASCII.GetBytes(asciiInput);
        var digest = SHA1.ComputeHash(message);

        Assert.Equal(expectedHex, Convert.ToHexStringLower(digest));
    }

    [Fact]
    public void ComputeHash_EmptyMessage_MatchesKnownAnswer() {
        var digest = SHA1.ComputeHash(Array.Empty<byte>());
        Assert.Equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", Convert.ToHexStringLower(digest));
    }

    [Fact]
    public void ComputeHash_OneMillionRepeatedChars_MatchesKnownAnswer() {
        // This is one of the standard "stress test" vectors for SHA-1
        // implementations (a million repetitions of the character 'a'),
        // and also exercises many, many block boundaries.
        var message = Encoding.ASCII.GetBytes(new string('a', 1_000_000));
        var digest = SHA1.ComputeHash(message);

        Assert.Equal("34aa973cd4c4daa4f61eeb2bdbad27316534016f", Convert.ToHexStringLower(digest));
    }

    [Fact]
    public void ComputeHash_IsDeterministic() {
        var message = Encoding.UTF8.GetBytes("Determinism check, take 2.");

        var first = SHA1.ComputeHash(message);
        var second = SHA1.ComputeHash(message);

        Assert.Equal(first, second);
    }

    [Fact]
    public void ComputeHash_DifferentMessages_ProduceDifferentDigests() {
        var a = SHA1.ComputeHash(Encoding.ASCII.GetBytes("message A"));
        var b = SHA1.ComputeHash(Encoding.ASCII.GetBytes("message B"));

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeHash_ProducesTwentyByteDigest() {
        var digest = SHA1.ComputeHash(Encoding.ASCII.GetBytes("any input at all"));
        Assert.Equal(SHA1.DigestSizeBytes, digest.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(55)]
    [InlineData(56)]
    [InlineData(57)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1000)]
    public void ApplyPadding_AlwaysProducesWholeNumberOfBlocks(int messageLength) {
        var message = new byte[messageLength];
        var padded = SHA1.ApplyPadding(message);

        Assert.Equal(0, padded.Length % SHA1.BlockSizeBytes);
        Assert.True(padded.Length >= messageLength + 9);
    }

    [Fact]
    public void ComputePadding_EmptyMessage_IsExactlyOneBlock() {
        var padding = SHA1.ComputePadding(0);

        Assert.Equal(64, padding.Length);
        Assert.Equal(0x80, padding[0]);
        for (var i = 1; i < 63; i++) {
            Assert.Equal(0, padding[i]);
        }
        Assert.Equal(0, padding[63]);
    }

    [Fact]
    public void ComputePadding_EncodesLengthAsBigEndianBits() {
        var padding = SHA1.ComputePadding(1);

        var lengthField = padding[^8..];
        byte[] expected = { 0, 0, 0, 0, 0, 0, 0, 8 };
        Assert.Equal(expected, lengthField);
    }

    [Fact]
    public void ComputePadding_AtFiftySixBytes_RequiresAFullExtraBlock() {
        var padding = SHA1.ComputePadding(56);
        Assert.Equal(72, padding.Length);
        Assert.Equal(0, (56 + padding.Length) % SHA1.BlockSizeBytes);
    }

}
