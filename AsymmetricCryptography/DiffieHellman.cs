using System.Numerics;
using System.Security.Cryptography;
using MathUtils;

namespace AsymmetricCryptography;

/// <summary>
/// Implementation of unauthenticated Diffie-Hellman.
/// </summary>
public class DiffieHellman {

    #region Record types

    /// <summary>
    /// Diffie-Hellman group parameters.
    /// </summary>
    /// <param name="Modulus">The modulus for group operations.</param>
    /// <param name="Generator">The generator for group operations.</param>
    /// <param name="Order">The order of the generator <c>g</c>.</param>
    public record struct Parameters(BigInteger Modulus, BigInteger Generator, BigInteger Order);

    #endregion

    #region Configuration

    /// <summary>The smallest modulus bit length this implementation will generate.</summary>
    public const int MinimumBitLength = 32;
    private Parameters Params;
    private BigInteger PrivateValue;
    private BigInteger PublicValue;

    #endregion

    #region Key retrieval

    /// <summary>Returns the parameters held by this instance.</summary>
    public Parameters GetParameters() => Params;

    /// <summary>Returns the public key held by this instance.</summary>
    public BigInteger GetPublicValue() => PublicValue;

    #endregion

    #region Constructors

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates parameters and key pair.
    /// </summary>
    /// <param name="bitLength">Modulus size in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="bitLength"/> is below <see cref="MinimumBitLength"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="bitLength"/> is odd.</exception>
    public DiffieHellman(int bitLength) {
        if (bitLength < MinimumBitLength) throw new ArgumentOutOfRangeException();
        if ((bitLength & 1) == 1) throw new ArgumentException();

        (BigInteger p, BigInteger q) = AsymmetricUtils.GetRandomSafePrime(bitLength);
        BigInteger g;
        while (true)
        {
            g = AsymmetricUtils.GetRandom(new BigInteger(2), p - new BigInteger(2));
            if (g.ModExp(q, p) == BigInteger.One) break;
        }
        Params = new Parameters(p, g, q);

        PrivateValue = AsymmetricUtils.GetRandom(BigInteger.One, q - BigInteger.One);
        PublicValue = g.ModExp(PrivateValue, p);
    }

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
    /// </summary>
    /// <param name="parameters">Parameters to use when generating the key pair.</param>
    public DiffieHellman(Parameters parameters) {
        if (parameters.Modulus != (parameters.Order << 1) + BigInteger.One) throw new ArgumentException();
        if (parameters.Generator.ModExp(parameters.Order, parameters.Modulus) != BigInteger.One) throw new ArgumentException();
        if (parameters.Generator == BigInteger.One || parameters.Generator == parameters.Modulus - BigInteger.One) throw new ArgumentException();

        Params = parameters;
        PrivateValue = AsymmetricUtils.GetRandom(BigInteger.One, parameters.Order - BigInteger.One);
        PublicValue = parameters.Generator.ModExp(PrivateValue, parameters.Modulus);
    }

    #endregion

    #region Operations

    /// <summary>
    /// Combines a received public value with the local private key to calculate a shared value.
    /// </summary>
    /// <param name="receivedPublicValue">The peer's public value.</param>
    /// <returns>The calculated shared value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicValue"/> is not within the group.</exception>
    public BigInteger ComputeSharedValue(BigInteger receivedPublicValue) {
        if (receivedPublicValue <= BigInteger.One) throw new ArgumentOutOfRangeException();
        if (receivedPublicValue.ModExp(Params.Order, Params.Modulus) != BigInteger.One) throw new ArgumentOutOfRangeException();
        return receivedPublicValue.ModExp(PrivateValue, Params.Modulus);
    }

    /// <summary>
    /// Combines a received public value with the local private key to derive a shared key using HKDF w/ SHA-512.
    /// </summary>
    /// <param name="receivedPublicValue">The peer's public value.</param>
    /// <param name="byteCount">The desired number of bytes in the shared key.</param>
    /// <returns>A shared key derived from calculating shared value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicValue"/> is not within the group or byteCount is not positive.</exception>
    /// <remarks>
    /// Use <see cref="HKDF.DeriveKey" /> method to generate a key, using <see cref="HashAlgorithmName.SHA512"/>
    /// as the hash algorithm.
    /// </remarks>
    public byte[] ComputeSharedKey(BigInteger receivedPublicValue, int byteCount) {
        return HKDF.DeriveKey(HashAlgorithmName.SHA512, ComputeSharedValue(receivedPublicValue).ToByteArray(((int) Params.Order.GetBitLength() + 7) / 8), byteCount);
    }

    #endregion

}
