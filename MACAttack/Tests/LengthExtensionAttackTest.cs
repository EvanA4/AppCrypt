// ============================================================================
// LengthExtensionAttackTests.cs
//
// Tests for LengthExtensionAttack.cs. Each test is written to be a
// complete, self-contained worked example: pick a key and message, act
// as the "server" to compute a legitimate MAC, then act as the
// "attacker" (who never touches the key directly) to forge an extended
// message and MAC, and finally verify the forgery the way a real,
// naive server would -- by recomputing SHA1(key || forgedMessage) and
// checking it matches.
//
// These are meant to be read in class alongside LengthExtensionAttack.cs
// itself -- feel free to add breakpoints/console output when walking
// through them live.
// ============================================================================

using System.Text;
using Xunit;

namespace MACAttack.Tests;

public class LengthExtensionAttackTests {
    // ------------------------------------------------------------------
    // Small local helper mirroring how a real (insecure!) server would
    // verify a request: recompute SHA1(key || message) and compare.
    // ------------------------------------------------------------------
    private static bool ServerAccepts(byte[] key, byte[] message, byte[] claimedMac) {
        var recomputed = MAC.ComputeMAC(key, message);
        return recomputed.AsSpan().SequenceEqual(claimedMac);
    }

    // ====================================================================
    // WORKED EXAMPLE 1: the classic "&admin=true" privilege escalation.
    //
    // This mirrors a very common textbook/CTF scenario: a web API signs
    // requests like "user=alice&admin=false" with MAC = SHA1(key || body),
    // and a naive server trusts any request whose MAC checks out. An
    // attacker who observes one such (body, MAC) pair can splice on
    // "&admin=true" without ever learning the key.
    // ====================================================================
    [Fact]
    public void Extend_ClassicAdminEscalation_ForgedMacIsAcceptedByServer() {
        // --- Server side: only the server knows `key`. ---
        var key = Encoding.ASCII.GetBytes("s3cr3t!!"); // 8-byte key
        var originalMessage = Encoding.ASCII.GetBytes("user=alice&admin=false");
        var originalMac = MAC.ComputeMAC(key, originalMessage);

        // Sanity check: the legitimate message verifies normally.
        Assert.True(ServerAccepts(key, originalMessage, originalMac));

        // --- Attacker side: knows originalMessage, originalMac, and the
        // key's LENGTH (8 bytes) -- but never sees `key`'s contents. ---
        var extension = Encoding.ASCII.GetBytes("&admin=true");
        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, extension, keyLengthBytes: key.Length);

        // --- Verification: the server re-checks the forged request the
        // same insecure way it always does. ---
        Assert.True(ServerAccepts(key, forged.NewMessage, forged.NewMAC));

        // The forged message should end with the attacker's extension,
        // and should be strictly longer than original+extension because
        // of the glue padding sitting in the middle.
        var forgedText = Encoding.Latin1.GetString(forged.NewMessage);
        Assert.EndsWith("&admin=true", forgedText);
        Assert.True(forged.NewMessage.Length > originalMessage.Length + extension.Length);
    }

    // ====================================================================
    // WORKED EXAMPLE 2: same idea, but walked through with an even
    // shorter message and key so the glue padding is easy to reason
    // about by hand (useful for a whiteboard walkthrough).
    // ====================================================================
    [Fact]
    public void Extend_ShortMessageAndKey_ForgedMacIsAcceptedByServer() {
        var key = Encoding.ASCII.GetBytes("key");      // 3 bytes
        var originalMessage = Encoding.ASCII.GetBytes("data"); // 4 bytes
        // key||message is only 7 bytes -- comfortably fits in a single
        // 64-byte block once padded, which makes this a good "smallest
        // possible case" example to step through with a debugger.
        var originalMac = MAC.ComputeMAC(key, originalMessage);

        var extension = Encoding.ASCII.GetBytes("EXTRA");
        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, extension, keyLengthBytes: key.Length);

        Assert.True(ServerAccepts(key, forged.NewMessage, forged.NewMAC));
    }

    // ====================================================================
    // WORKED EXAMPLE 3: an empty extension. Somewhat degenerate, but
    // worth testing explicitly -- the forged message should just be
    // originalMessage + gluePadding, and the forged MAC should equal
    // SHA1(key || originalMessage || gluePadding), which the server will
    // accept just as readily as the original.
    // ====================================================================
    [Fact]
    public void Extend_EmptyExtension_StillProducesValidForgery() {
        var key = Encoding.ASCII.GetBytes("anotherkey");
        var originalMessage = Encoding.ASCII.GetBytes("some data here");
        var originalMac = MAC.ComputeMAC(key, originalMessage);

        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, Array.Empty<byte>(), keyLengthBytes: key.Length);

        Assert.True(ServerAccepts(key, forged.NewMessage, forged.NewMAC));
        // With no extension, the forged message is exactly the original
        // message plus glue padding.
        Assert.True(forged.NewMessage.Length > originalMessage.Length);
    }

    // ====================================================================
    // WORKED EXAMPLE 4: chained/repeated attacks. An attacker can take a
    // forged (message, MAC) pair and use it as the STARTING POINT for a
    // second extension, chaining attacks arbitrarily. This models an
    // attacker who extends a request more than once (perhaps
    // experimenting, or building up a longer payload incrementally).
    // ====================================================================
    [Fact]
    public void Extend_CanBeChainedMultipleTimes() {
        var key = Encoding.ASCII.GetBytes("chain-key-12345");
        var originalMessage = Encoding.ASCII.GetBytes("step0");
        var originalMac = MAC.ComputeMAC(key, originalMessage);

        var afterFirstExtension = LengthExtensionAttack.Extend(
            originalMessage, originalMac, Encoding.ASCII.GetBytes("-step1"), keyLengthBytes: key.Length);
        Assert.True(ServerAccepts(key, afterFirstExtension.NewMessage, afterFirstExtension.NewMAC));

        // Now extend AGAIN, starting from the forged pair above. Note
        // the "key length" for this second hop is the length of the
        // ENTIRE previous forged message plus the original key -- from
        // the hash function's point of view, `afterFirstExtension.NewMessage`
        // is now just "the message", and the (unknown) prefix in front
        // of it is still exactly `key` (the attacker still never learns
        // it).
        var afterSecondExtension = LengthExtensionAttack.Extend(
            afterFirstExtension.NewMessage,
            afterFirstExtension.NewMAC,
            Encoding.ASCII.GetBytes("-step2"),
            keyLengthBytes: key.Length);

        Assert.True(ServerAccepts(key, afterSecondExtension.NewMessage, afterSecondExtension.NewMAC));

        var finalText = Encoding.Latin1.GetString(afterSecondExtension.NewMessage);
        Assert.EndsWith("-step2", finalText);
    }

    // ====================================================================
    // WORKED EXAMPLE 5: varying key lengths, including block-boundary
    // edge cases (0 bytes, and lengths that push key||message right up
    // against a 64-byte block boundary). This is the scenario an
    // attacker faces when they must brute-force an unknown key length by
    // trying several candidates.
    // ====================================================================
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(55)]  // key length alone already lands near the padding boundary
    [InlineData(64)]  // key length alone is exactly one block
    [InlineData(100)]
    public void Extend_WorksForVariousKeyLengths(int keyLength) {
        var key = new byte[keyLength];
        new Random(Seed: keyLength).NextBytes(key); // deterministic but "random-looking" key bytes

        var originalMessage = Encoding.ASCII.GetBytes("some request body");
        var originalMac = MAC.ComputeMAC(key, originalMessage);

        var extension = Encoding.ASCII.GetBytes("&injected=1");
        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, extension, keyLengthBytes: keyLength);

        Assert.True(ServerAccepts(key, forged.NewMessage, forged.NewMAC));
    }

    // ====================================================================
    // WORKED EXAMPLE 6: varying original message lengths, again
    // including values right around the 56/64-byte padding boundaries,
    // since off-by-one errors in padding math are the most common bug in
    // a from-scratch implementation of this attack.
    // ====================================================================
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(55)]
    [InlineData(56)]
    [InlineData(57)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(200)]
    public void Extend_WorksForVariousMessageLengths(int messageLength) {
        var key = Encoding.ASCII.GetBytes("fixed-key");
        var originalMessage = new byte[messageLength];
        new Random(Seed: messageLength + 1000).NextBytes(originalMessage);

        var originalMac = MAC.ComputeMAC(key, originalMessage);

        var extension = Encoding.ASCII.GetBytes("EXTENSION");
        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, extension, keyLengthBytes: key.Length);

        Assert.True(ServerAccepts(key, forged.NewMessage, forged.NewMAC));
    }

    // ====================================================================
    // WORKED EXAMPLE 7: a long, multi-block extension, to confirm the
    // attack correctly processes more than one additional block after
    // resuming from the borrowed state.
    // ====================================================================
    [Fact]
    public void Extend_WithMultiBlockExtension_StillProducesValidForgery() {
        var key = Encoding.ASCII.GetBytes("multiblock-key");
        var originalMessage = Encoding.ASCII.GetBytes("short message");
        var originalMac = MAC.ComputeMAC(key, originalMessage);

        // 300 bytes guarantees the extension alone spans multiple 64-byte blocks.
        var extension = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("payload-chunk;", 25)));
        Assert.True(extension.Length > SHA1.BlockSizeBytes * 4);

        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, extension, keyLengthBytes: key.Length);

        Assert.True(ServerAccepts(key, forged.NewMessage, forged.NewMAC));
    }

    // ====================================================================
    // Negative examples: demonstrate that the "obvious naive fixes" a
    // student might reach for don't work, and that a wrong guess at the
    // key length correctly produces a MISMATCHED mac (i.e. the attack
    // silently fails safely, it doesn't happen to work "by accident").
    // ====================================================================

    [Fact]
    public void Extend_WithWrongKeyLength_ProducesMacThatServerRejects() {
        var key = Encoding.ASCII.GetBytes("s3cr3t!!"); // actually 8 bytes
        var originalMessage = Encoding.ASCII.GetBytes("user=alice&admin=false");
        var originalMac = MAC.ComputeMAC(key, originalMessage);

        var extension = Encoding.ASCII.GetBytes("&admin=true");

        // Attacker GUESSES the wrong key length (16 instead of 8 bytes).
        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, extension, keyLengthBytes: 16);

        // The forgery computed against the WRONG assumed key length does
        // not verify against the REAL key -- this is exactly why real
        // attacks need to know or brute-force the true key length.
        Assert.False(ServerAccepts(key, forged.NewMessage, forged.NewMAC));
    }

    [Fact]
    public void Extend_RejectsMacOfWrongLength() {
        var tooShortMac = new byte[10]; // a real SHA-1 MAC is 20 bytes
        Assert.Throws<ArgumentException>(() =>
            LengthExtensionAttack.Extend(
                Encoding.ASCII.GetBytes("msg"), tooShortMac, Encoding.ASCII.GetBytes("ext"), keyLengthBytes: 8));
    }

    [Fact]
    public void Extend_RejectsNegativeKeyLength() {
        var validMac = new byte[SHA1.DigestSizeBytes];
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            LengthExtensionAttack.Extend(
                Encoding.ASCII.GetBytes("msg"), validMac, Encoding.ASCII.GetBytes("ext"), keyLengthBytes: -1));
    }

    // ====================================================================
    // Structural test: confirm the forged message really is built as
    // originalMessage || gluePadding || extension, with the glue padding
    // being exactly SHA1.ComputePadding of the key+message length -- i.e.
    // confirm the "attack" isn't accidentally doing something else that
    // merely happens to produce a matching MAC.
    // ====================================================================
    [Fact]
    public void Extend_NewMessageStructure_IsOriginalPlusGluePaddingPlusExtension() {
        var key = Encoding.ASCII.GetBytes("012345"); // 6 bytes
        var originalMessage = Encoding.ASCII.GetBytes("hello");
        var originalMac = MAC.ComputeMAC(key, originalMessage);
        var extension = Encoding.ASCII.GetBytes("world");

        var forged = LengthExtensionAttack.Extend(
            originalMessage, originalMac, extension, keyLengthBytes: key.Length);

        var expectedGluePadding = SHA1.ComputePadding(key.Length + originalMessage.Length);

        var expectedNewMessage = originalMessage
            .Concat(expectedGluePadding)
            .Concat(extension)
            .ToArray();

        Assert.Equal(expectedNewMessage, forged.NewMessage);
    }

    // ====================================================================
    // ComputeInsecureMac helper tests: mostly here to document why this
    // construction is called "insecure" -- e.g. two different
    // (key, message) pairs that happen to produce the same key||message
    // concatenation will collide.
    // ====================================================================
    [Fact]
    public void ComputeInsecureMac_MatchesDirectConcatenationHash() {
        var key = Encoding.ASCII.GetBytes("k");
        var message = Encoding.ASCII.GetBytes("m");

        var mac = MAC.ComputeMAC(key, message);
        var direct = SHA1.ComputeHash(Encoding.ASCII.GetBytes("km"));

        Assert.Equal(direct, mac);
    }

    [Fact]
    public void ComputeInsecureMac_AmbiguousKeyMessageBoundary_Collides() {
        // This is a SEPARATE, classic weakness of MAC = H(key || message)
        // (distinct from the length-extension attack): without a length
        // prefix or separator, ("ab", "c") and ("a", "bc") are
        // indistinguishable once concatenated, so they produce the SAME
        // MAC despite being (key, message) pairs a naive implementer
        // might expect to be unrelated.
        var mac1 = MAC.ComputeMAC(
            Encoding.ASCII.GetBytes("ab"), Encoding.ASCII.GetBytes("c"));
        var mac2 = MAC.ComputeMAC(
            Encoding.ASCII.GetBytes("a"), Encoding.ASCII.GetBytes("bc"));

        Assert.Equal(mac1, mac2);
    }
}
