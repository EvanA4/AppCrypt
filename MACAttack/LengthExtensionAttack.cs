namespace MACAttack;

/// <summary>
/// Implements a SHA-1 length-extension attack against the insecure
/// MAC construction MAC = SHA1(key || message).
/// </summary>
public static class LengthExtensionAttack {

    #region Record types

    /// <summary>
    /// Result of a successful SHA-1 length-extension attack: a new message
    /// and a valid MAC for that message.
    /// </summary>
    /// <param name="NewMessage">New message that the receiver will validate.</param>
    /// <param name="NewMAC">New MAC that is valid for <paramref name="NewMessage"/></param>
    public readonly record struct LengthExtensionResult(byte[] NewMessage, byte[] NewMAC);

    #endregion

    /// <summary>
    /// Given a message and its MAC (computed as <c>SHA1(key || message)</c>
    /// with a secret, unknown key), forges a new message/MAC pair that
    /// appends <paramref name="extension"/> to the original message
    /// without ever learning the key.
    /// </summary>
    /// <param name="originalMessage">The original message.</param>
    /// <param name="originalMac">The original, valid MAC for <paramref name="originalMessage"/></param>
    /// <param name="extension">The attacker-chosen bytes to append, e.g. "&amp;admin=true".</param>
    /// <param name="keyLengthBytes">The length, in bytes, of the secret key.</param>
    /// <returns>The forged (message, MAC) pair.</returns>
    public static LengthExtensionResult Extend(
        byte[] originalMessage, byte[] originalMac, byte[] extension, int keyLengthBytes) {
        
        if (keyLengthBytes < 0) throw new ArgumentOutOfRangeException();
        if (originalMac.Length != 20) throw new ArgumentException();

        // compute next MAC
        byte[] originalPadding = SHA1.ComputePadding(keyLengthBytes + originalMessage.Length);
        byte[] padding = SHA1.ComputePadding(keyLengthBytes + originalMessage.Length + originalPadding.Length + extension.Length);

        byte[] sum = new byte[extension.Length + padding.Length];
        for (int i = 0; i < extension.Length; ++i) sum[i] = extension[i];
        for (int i = 0; i < padding.Length; ++i) sum[extension.Length + i] = padding[i];

        uint[] originalMacInts = SHA1.ToInts(originalMac);
        SHA1.ProcessData(originalMacInts, sum);
        byte[] newMac = SHA1.ToBytes(originalMacInts);

        // compute verified message
        byte[] newMessage = new byte[originalMessage.Length + originalPadding.Length + extension.Length];
        for (int i = 0; i < originalMessage.Length; ++i) newMessage[i] = originalMessage[i];
        for (int i = 0; i < originalPadding.Length; ++i) newMessage[i + originalMessage.Length] = originalPadding[i];
        for (int i = 0; i < extension.Length; ++i) newMessage[i + originalMessage.Length + originalPadding.Length] = extension[i];

        // return result
        return new LengthExtensionResult(newMessage, newMac);
    }

}
