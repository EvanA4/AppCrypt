using System.Numerics;
using System.Security.Cryptography;
using MathUtils;
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
    public Parameters GetParameters() => parameters;

    /// <summary>Returns the public key held by this instance.</summary>
    public ECPoint GetPublicValue() => publicKey;

    #endregion

    #region Constructors

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
    /// </summary>
    /// <param name="parameters">Parameters to use when generating the key pair.</param>
    public ECDiffieHellman(Parameters parameters) {
        if (parameters.Curve.P < 5) throw new ArgumentException();
        if (parameters.Generator == ECPoint.PointAtInfinity) throw new ArgumentException();
        if (parameters.Order * parameters.Generator != ECPoint.PointAtInfinity) throw new ArgumentException();

        this.parameters = parameters;
        privateKey = AsymmetricUtils.GetRandom(BigInteger.One, parameters.Order - BigInteger.One);
        publicKey = privateKey * parameters.Generator;
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
        var x = receivedPublicPoint.X;
        var y = receivedPublicPoint.Y;
        var p = parameters.Curve.P;
        var a = parameters.Curve.A;
        var b = parameters.Curve.B;
        var ySquared = y.ModMultiply(y, p);
        var ySquaredCalculated = x.ModExp(new BigInteger(3), p).ModAdd(a.ModMultiply(x, p), p).ModAdd(b, p);
        
        if (ySquared != ySquaredCalculated) throw new ArgumentOutOfRangeException();
        if (parameters.Order * receivedPublicPoint != ECPoint.PointAtInfinity) throw new ArgumentOutOfRangeException();

        return privateKey * receivedPublicPoint;
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
        if (byteCount <= 0) throw new ArgumentOutOfRangeException();

        var rawShared = ComputeSharedPoint(receivedPublicPoint);
        var byteLength = ((int) parameters.Curve.P.GetBitLength() + 7) / 8;
        var rawSharedBytes = rawShared.X.ToByteArray(isUnsigned: true, isBigEndian: true);

        // Left-pad to the same fixed length the implementation uses.
        if (rawSharedBytes.Length < byteLength) {
            var padded = new byte[byteLength];
            Array.Copy(rawSharedBytes, 0, padded, byteLength - rawSharedBytes.Length, rawSharedBytes.Length);
            rawSharedBytes = padded;
        }

        return HKDF.DeriveKey(HashAlgorithmName.SHA512, rawSharedBytes, byteCount);
    }

    #endregion
}
