using System.Numerics;

namespace MathUtils;

/// <summary>
/// Represents an elliptic curve over a finite field.
/// </summary>
public readonly record struct ECCurve {

    #region Members

    /// <summary>Linear coefficient <c>A</c> of the curve equation.</summary>
    public BigInteger A { get; }

    /// <summary>Constant coefficient <c>B</c> of the curve equation.</summary>
    public BigInteger B { get; }

    /// <summary>Prime modulus of the curve.</summary>
    public BigInteger P { get; }

    #endregion

    #region Constructor

    /// <summary>
    /// Initializes a new instance of the <see cref="ECCurve"/> struct with the specified coefficients and prime modulus.
    /// </summary>
    /// <param name="a">The coefficient <c>A</c>.</param>
    /// <param name="b">The coefficient <c>B</c>.</param>
    /// <param name="p">The prime modulus <c>P</c>.</param>
    /// <exception cref="ArgumentException">Thrown when the given parameters do not produce a non-singular elliptic curve.</exception>
    public ECCurve(BigInteger a, BigInteger b, BigInteger p) {
        a = a.Mod(p);
        b = b.Mod(p);

        if (!IsValidCurve(a, b, p)) throw new ArgumentException("The given curve is not a valid elliptic curve.");

        A = a;
        B = b;
        P = p;
    }

    #endregion

    #region Operation

    /// <summary>
    /// Deconstructs the elliptic curve into its constituent components.
    /// </summary>
    /// <param name="a">Outputs the linear coefficient <c>A</c>.</param>
    /// <param name="b">Outputs the constant coefficient <c>B</c>.</param>
    /// <param name="p">Outputs the prime modulus <c>P</c>.</param>
    /// <remarks>
    /// Your implementation needs to make sure the point is on the curve.
    /// </remarks>
    public void Deconstruct(out BigInteger a, out BigInteger b, out BigInteger p) {
        a = A;
        b = B;
        p = P;
    }

    /// <summary>
    /// Determines whether the specified coefficients and prime modulus form a valid (non-singular) elliptic curve.
    /// </summary>
    /// <param name="a">The coefficient <c>A</c>.</param>
    /// <param name="b">The coefficient <c>B</c>.</param>
    /// <param name="p">The prime modulus <c>P</c>.</param>
    /// <returns><see langword="true"/> if the discriminant is non-zero modulo <c>P</c>.</returns>
    public static bool IsValidCurve(BigInteger a, BigInteger b, BigInteger p) {
        var discriminant = new BigInteger(16).ModMultiply(
            new BigInteger(4).ModMultiply(a.ModExp(new BigInteger(3), p), p).ModAdd(
                new BigInteger(27).ModMultiply(b.ModMultiply(b, p), p), p), p);
        return discriminant != 0;
    }

    /// <summary>
    /// Constructs a point on the curve y² ≡ x³ + Ax + B (mod P).
    /// </summary>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    /// <returns>ECPoint for the given x and y.</returns>
    public ECPoint GetPoint(BigInteger x, BigInteger y) {
        x = x.Mod(P);
        y = y.Mod(P);

        var ySquared = y.ModMultiply(y, P);
        var ySquaredCalculated = x.ModExp(new BigInteger(3), P).ModAdd(A.ModMultiply(x, P), P).ModAdd(B, P);
        if (ySquared != ySquaredCalculated) throw new ArgumentException("The point (x,y) is not on this curve.");

        return new ECPoint(this, x, y);
    }

    /// <summary>
    /// Checks if the given coordinates are on the curve.
    /// </summary>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    /// <returns>True if the coordinates are on the curve, false otherwise.</returns>
    public bool AreCoordinatesOnCurve(BigInteger x, BigInteger y) {
        return y.ModMultiply(y, P) == x.ModExp(new BigInteger(3), P).ModAdd(A.ModMultiply(x, P), P).ModAdd(B, P);
    }

    #endregion
}

/// <summary>
/// Represents a point on an elliptic curve, or the identity element (point at infinity).
/// </summary>
public readonly record struct ECPoint {

    #region Members

    /// <summary>Gets the elliptic curve to which this point belongs.</summary>
    private ECCurve E { get; }

    /// <summary>Gets the x-coordinate of the point.</summary>
    public BigInteger X { get; }

    /// <summary>Gets the y-coordinate of the point.</summary>
    public BigInteger Y { get; }

    #endregion

    #region Point at infinity

    /// <summary>Gets the identity element (point at infinity) for elliptic curve arithmetic.</summary>
    public static ECPoint PointAtInfinity { get; } = default;

    #endregion

    #region Constructor

    /// <summary>
    /// Constructs a finite point on the given curve.
    /// </summary>
    /// <param name="e">Curve the point belongs to.</param>
    /// <param name="x">X coordinate of the point (must be non-negative).</param>
    /// <param name="y">Y coordinate of the point (must be non-negative).</param>
    internal ECPoint(ECCurve e, BigInteger x, BigInteger y) {
        E = e;
        X = x.Mod(e.P);
        Y = y.Mod(e.P);
    }

    #endregion

    #region Operation

    /// <summary>
    /// Deconstructs the point into its associated curve and coordinates.
    /// </summary>
    /// <param name="e">Outputs the curve.</param>
    /// <param name="x">Outputs the x-coordinate.</param>
    /// <param name="y">Outputs the y-coordinate.</param>
    public void Deconstruct(out ECCurve e, out BigInteger x, out BigInteger y) {
        e = E;
        x = X;
        y = Y;
    }

    #endregion

    #region Operator overloads

    /// <summary>
    /// Negates the specified point, producing its additive inverse on the curve.
    /// </summary>
    /// <param name="value">The point to negate.</param>
    /// <returns>The negated point.</returns>
    public static ECPoint operator -(ECPoint value) {
        return new ECPoint(
            value.E,
            value.X,
            value.Y * -1
        );
    }

    /// <summary>
    /// Adds two points on an elliptic curve.
    /// </summary>
    /// <param name="lhs">The first point.</param>
    /// <param name="rhs">The second point.</param>
    /// <returns>The resulting point of the addition.</returns>
    /// <exception cref="ArgumentException">Thrown when attempting to add points from different elliptic curves.</exception>
    public static ECPoint operator +(ECPoint lhs, ECPoint rhs) {
        // Edge case: one point is infinity
        if (lhs == PointAtInfinity && rhs != PointAtInfinity)
            return rhs;
        else if (lhs != PointAtInfinity && rhs == PointAtInfinity)
            return lhs;

        // Edge case: both points are infinity
        if (lhs == PointAtInfinity && rhs == PointAtInfinity)
            return lhs;

        // Argument Exceptions:
        if (
            lhs.E.A != rhs.E.A ||
            lhs.E.B != rhs.E.B ||
            lhs.E.P != rhs.E.P
        )
        {
            throw new ArgumentException();
        }

        // 4 cases:
        BigInteger lambda, outx, outy;

        // Case 2: P + P = R
        // Exception: y=0 causes P+P to = PointAtInfinity
        if (
            lhs.X == rhs.X &&
            lhs.Y == rhs.Y
        )
        {
            if (lhs.Y == BigInteger.Zero)
                return PointAtInfinity;

            lambda = new BigInteger(3).ModMultiply(lhs.X.ModMultiply(lhs.X, lhs.E.P), lhs.E.P).ModAdd(lhs.E.A, lhs.E.P)
                .ModDivide(new BigInteger(2).ModMultiply(lhs.Y, lhs.E.P), lhs.E.P);
            outx = lambda.ModMultiply(lambda, lhs.E.P).ModSubstract(new BigInteger(2).ModMultiply(lhs.X, lhs.E.P), lhs.E.P);
            outy = lambda.ModMultiply(lhs.X.ModSubstract(outx, lhs.E.P), lhs.E.P).ModSubstract(lhs.Y, lhs.E.P);
            return new ECPoint(lhs.E, outx, outy);
        }

        // Case 3: P - P = 0
        if (
            lhs.X == rhs.X &&
            lhs.Y == rhs.Y.ModMultiply(new BigInteger(-1), lhs.E.P)
        )
            return PointAtInfinity;

        // Case 4: P + Q = 0 (no intersection)
        if (lhs.X.ModSubstract(rhs.X, lhs.E.P) == BigInteger.Zero)
            return PointAtInfinity;

        // Case 1: P + Q = R (intersection)
        lambda = rhs.Y.ModSubstract(lhs.Y, lhs.E.P)
            .ModDivide(rhs.X.ModSubstract(lhs.X, lhs.E.P), lhs.E.P);
        outx = lambda.ModMultiply(lambda, lhs.E.P).ModSubstract(lhs.X, lhs.E.P).ModSubstract(rhs.X, lhs.E.P);
        outy = lambda.ModMultiply(lhs.X.ModSubstract(outx, lhs.E.P), lhs.E.P).ModSubstract(lhs.Y, lhs.E.P);
        return new ECPoint(lhs.E, outx, outy);
    }

    /// <summary>
    /// Multiplies an elliptic curve point by a scalar using double-and-add scalar multiplication.
    /// </summary>
    /// <param name="k">The scalar multiplier.</param>
    /// <param name="point">The point to multiply.</param>
    /// <returns>The point <c>k * point</c>.</returns>
    /// <remarks>
    /// You must implement this function efficiently.
    /// At most, you may use <see cref="operator +" /> Ceiling(log2(base)) + #bits_set(k)) times.
    /// You are only allowed a single <see cref="ECPoint"/>  for local variables.
    /// </remarks>
    public static ECPoint operator *(BigInteger k, ECPoint point) {
        if (k == BigInteger.Zero)
            return PointAtInfinity;
        if (k < BigInteger.Zero)
        {
            point = -point;
            k *= new BigInteger(-1);
        }

        ECPoint output = PointAtInfinity;
        while (k > BigInteger.Zero)
        {
            if ((k & BigInteger.One) != BigInteger.Zero)
                output += point;
            k >>= 1;
            point += point;
        }

        return output;
    }

    #endregion
}
