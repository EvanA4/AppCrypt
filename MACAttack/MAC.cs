namespace MACAttack;

public static class MAC {

    /// <summary>
    /// Generates a MAC of a message using MAC = SHA1(key || data).
    /// </summary>
    /// <param name=C"key">Shared key that provides the integrity to the MAC</param>
    /// <param name="data">The data for which to generate the MAC</param>
    /// <returns>A MAC for the given key and data.</returns>
    public static byte[] ComputeMAC(byte[] key, byte[] data) {
        throw new NotImplementedException();
    }

}