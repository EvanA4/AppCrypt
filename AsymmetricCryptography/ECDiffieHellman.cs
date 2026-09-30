using System.Numerics;
using System.Security.Cryptography;

using ECCurve = MathUtils.ECCurve;
using ECPoint = MathUtils.ECPoint;
using Parameters = AsymmetricCryptography.ECParameters.Parameters;

namespace AsymmetricCryptography;

/// <summary>
/// Implementation of unauthenticated Elliptic Curve Diffie-Hellman key agreement over a
/// prime-order subgroup of the multiplicative group of integers modulo a safe prime.
/// </summary>
public class ECDiffieHellman {

    #region Members

    /// <summary>The curve parameters.</summary>
    private readonly Parameters parameters;

    /// <summary>The public key.</summary>
    private readonly ECPoint publicKey;

    /// <summary>The private key.</summary>
    private readonly BigInteger privateKey;

    #endregion

    #region Key retrieval

    /// <summary>Returns the parameters held by this instance.</summary>
    public Parameters GetParameters() =>
            throw new NotImplementedException();

    /// <summary>Returns the public key held by this instance.</summary>
    public ECPoint GetPublicValue() =>
            throw new NotImplementedException();

    #endregion

    #region Constructors

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
    /// </summary>
    /// <param name="parameters">Parameters to use when generating the key pair.</param>
    public ECDiffieHellman(Parameters parameters) {
        throw new NotImplementedException();
    }

    #endregion

    #region Operations

    /// <summary>
    /// Combines a received public point with the local private key to calculate a shared point.
    /// </summary>
    /// <param name="receivedPublicPoint">The peer's public point.</param>
    /// <returns>The calculated shared point.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicPoint"/> is not within the group.</exception>
    public ECPoint ComputeSharedPoint(ECPoint receivedPublicPoint) {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Combines a received public point with the local private key to derive a shared key using HKDF w/ SHA-512.
    /// </summary>
    /// <param name="receivedPublicPoint">The peer's public point.</param>
    /// <param name="byteCount">The desired number of bytes in the shared key.</param>
    /// <returns>The calculated shared value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicPoint"/> is not within the group.</exception>
    /// <remarks>
    /// Use <see cref="HKDF.DeriveKey" /> method to generate a key, using <see cref="HashAlgorithmName.SHA512"/>
    /// as the hash algorithm.
    /// </remarks>
    public byte[] ComputeSharedKey(ECPoint receivedPublicPoint, int byteCount) {
        throw new NotImplementedException();
    }

    #endregion
}
