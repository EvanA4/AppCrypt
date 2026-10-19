using System.Text;
using Xunit;

namespace MACAttack.Tests;

public class MACTests {
    [Fact]
    public void ComputeMAC_MatchesDirectConcatenationHash() {
        var key = Encoding.ASCII.GetBytes("key");
        var data = Encoding.ASCII.GetBytes("data");

        var mac = MAC.ComputeMAC(key, data);
        var expected = SHA1.ComputeHash(Encoding.ASCII.GetBytes("keydata"));

        Assert.Equal(expected, mac);
    }

    [Fact]
    public void ComputeMAC_ProducesTwentyByteMac() {
        var mac = MAC.ComputeMAC(
            Encoding.ASCII.GetBytes("any-key"),
            Encoding.ASCII.GetBytes("any-data"));

        Assert.Equal(SHA1.DigestSizeBytes, mac.Length);
    }

    [Fact]
    public void ComputeMAC_IsDeterministic() {
        var key = Encoding.ASCII.GetBytes("consistent-key");
        var data = Encoding.ASCII.GetBytes("consistent-data");

        var first = MAC.ComputeMAC(key, data);
        var second = MAC.ComputeMAC(key, data);

        Assert.Equal(first, second);
    }

    [Fact]
    public void ComputeMAC_KnownAnswer_MatchesHandComputedValue() {
        var key = Encoding.ASCII.GetBytes("key");
        var data = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");

        var mac = MAC.ComputeMAC(key, data);

        Assert.Equal("2449ee34eb231c94f1d26a3285ab55e69b1ea4de", Convert.ToHexStringLower(mac));
    }

    [Fact]
    public void ComputeMAC_DifferentKeys_ProduceDifferentMacs() {
        var data = Encoding.ASCII.GetBytes("same data");

        var macA = MAC.ComputeMAC(Encoding.ASCII.GetBytes("key-a"), data);
        var macB = MAC.ComputeMAC(Encoding.ASCII.GetBytes("key-b"), data);

        Assert.NotEqual(macA, macB);
    }

    [Fact]
    public void ComputeMAC_DifferentData_ProduceDifferentMacs() {
        var key = Encoding.ASCII.GetBytes("same key");

        var macA = MAC.ComputeMAC(key, Encoding.ASCII.GetBytes("data A"));
        var macB = MAC.ComputeMAC(key, Encoding.ASCII.GetBytes("data B"));

        Assert.NotEqual(macA, macB);
    }

    [Fact]
    public void ComputeMAC_SingleBitFlipInData_ChangesMacCompletely() {
        var key = Encoding.ASCII.GetBytes("avalanche-key");
        var data = Encoding.ASCII.GetBytes("The quick brown fox");
        var flipped = (byte[])data.Clone();
        flipped[0] ^= 0x01;

        var macOriginal = MAC.ComputeMAC(key, data);
        var macFlipped = MAC.ComputeMAC(key, flipped);

        Assert.NotEqual(macOriginal, macFlipped);

        var differingBits = 0;
        for (var i = 0; i < macOriginal.Length; i++) {
            var xor = macOriginal[i] ^ macFlipped[i];
            differingBits += System.Numerics.BitOperations.PopCount((uint)xor);
        }
        Assert.True(differingBits > 20, $"Expected broad avalanche effect, only {differingBits}/160 bits differed.");
    }

    [Fact]
    public void ComputeMAC_EmptyKey_StillProducesValidMac() {
        var mac = MAC.ComputeMAC(Array.Empty<byte>(), Encoding.ASCII.GetBytes("data"));

        Assert.Equal(SHA1.DigestSizeBytes, mac.Length);
        Assert.Equal(SHA1.ComputeHash(Encoding.ASCII.GetBytes("data")), mac);
    }

    [Fact]
    public void ComputeMAC_EmptyData_StillProducesValidMac() {
        var mac = MAC.ComputeMAC(Encoding.ASCII.GetBytes("key"), Array.Empty<byte>());

        Assert.Equal(SHA1.DigestSizeBytes, mac.Length);
        Assert.Equal(SHA1.ComputeHash(Encoding.ASCII.GetBytes("key")), mac);
    }

    [Fact]
    public void ComputeMAC_EmptyKeyAndEmptyData_MatchesEmptyMessageHash() {
        var mac = MAC.ComputeMAC(Array.Empty<byte>(), Array.Empty<byte>());

        Assert.Equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", Convert.ToHexStringLower(mac));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(55)]
    [InlineData(56)]
    [InlineData(57)]
    [InlineData(64)]
    [InlineData(200)]
    public void ComputeMAC_WorksAcrossBlockBoundaries(int dataLength) {
        var key = Encoding.ASCII.GetBytes("boundary-key");
        var data = new byte[dataLength];
        new Random(Seed: dataLength).NextBytes(data);

        var mac = MAC.ComputeMAC(key, data);

        Assert.Equal(SHA1.DigestSizeBytes, mac.Length);
        Assert.Equal(SHA1.ComputeHash(key.Concat(data).ToArray()), mac);
    }

    // ------------------------------------------------------------------
    // A known, DISTINCT weakness of MAC = H(key || data), separate from
    // length extension: without a length prefix or delimiter recording
    // where the key ends and the data begins, two different (key, data)
    // splits of the same concatenated bytes are indistinguishable and
    // collide.
    // ------------------------------------------------------------------

    [Fact]
    public void ComputeMAC_AmbiguousKeyDataBoundary_Collides() {
        var macA = MAC.ComputeMAC(Encoding.ASCII.GetBytes("ab"), Encoding.ASCII.GetBytes("c"));
        var macB = MAC.ComputeMAC(Encoding.ASCII.GetBytes("a"), Encoding.ASCII.GetBytes("bc"));

        Assert.Equal(macA, macB);
    }

}
