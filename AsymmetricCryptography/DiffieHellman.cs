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

    #endregion

    #region Key retrieval

    /// <summary>Returns the parameters held by this instance.</summary>
    public Parameters GetParameters() =>
            throw new NotImplementedException();

    /// <summary>Returns the public key held by this instance.</summary>
    public BigInteger GetPublicValue() =>
            throw new NotImplementedException();

    #endregion

    #region Constructors

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates parameters and key pair.
    /// </summary>
    /// <param name="bitLength">Modulus size in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="bitLength"/> is below <see cref="MinimumBitLength"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="bitLength"/> is odd.</exception>
    public DiffieHellman(int bitLength) {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
    /// </summary>
    /// <param name="parameters">Parameters to use when generating the key pair.</param>
    public DiffieHellman(Parameters parameters) {
        throw new NotImplementedException();
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
        throw new NotImplementedException();
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
        throw new NotImplementedException();
    }

    #endregion

}
