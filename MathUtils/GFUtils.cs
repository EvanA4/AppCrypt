namespace MathUtils;

/// <summary>
/// Base class for implementing an Echo client.
/// </summary>
public static class GFUtils {

    /// <summary>
    /// The irreducible polynial for GF(2^8) used in AES (x^8 + x^4 + x^3 + x + 1).
    /// </summary>
    private const byte AESIrreduciblePolynomial = 0x1b;

    /// <summary>
    /// Calculates x * a(x) (mod p(x)) in GF(2^8).
    /// </summary>
    /// <param name="a">a(x).</param>
    /// <param name="p">p(x).</param>
    /// <returns>x * a(x) (mod p(x)) in GF(2^8).</returns>
    public static byte XTimes(byte a, byte p = AESIrreduciblePolynomial) {
        return (byte) ((a << 1) ^ ((a >> 7) & 1) * p);
    }

    /// <summary>
    /// Calculates a(x) * b(x) mod (mod p(x)) in GF(2^8).
    /// </summary>
    /// <param name="a">a(x)</param>
    /// <param name="b">b(x)</param>
    /// <returns>a(x) * b(x) mod (mod p(x)) in GF(2^8).</returns>
    /// <remarks>
    /// You must implement this function efficiently.
    /// At most, you may call <see cref="XTimes" /> at most seven times.
    /// You must calculate values as you go, not create a collection that stores values.
    /// </remarks>
    public static byte GFMultiply(byte a, byte b, byte p = AESIrreduciblePolynomial) {
        byte sum = (byte) ((a & 1) * b);
        
        // each x term:
        // update b with XTimes
        // add to sum if bit in a
        for (int i = 1; i < 8; ++i)
        {
            b = XTimes(b, p);
            sum ^= (byte) (((a >> i) & 1) * b);
        }
        return sum;
    }

}