using System.Numerics;

namespace MathUtils;

public static class BigIntegerExtensions {

    /// <summary>
    /// Computes the Greatest Common Divisor of a and b, along with the 
    /// Bézout coefficients u and v such that: (a * u) + (b * v) = gcd(a, b).
    /// </summary>
    /// <param name="a">First integer.</param>
    /// <param name="b">Second integer.</param>
    /// <returns>A tuple (gcd, x, y), where gcd is the GCD of a and b,
    /// and x, y are the Bézout coefficients.</returns>
    /// <remarks>
    /// Your implementation will need to handle the case that gcd(a, 0) = gcd(0, a) = a.
    /// </remarks>
    public static (BigInteger gcd, BigInteger u, BigInteger v) ExtendedEuclidean(BigInteger a, BigInteger b) {
        // checking for 0's
        if (a == BigInteger.Zero && b == BigInteger.Zero)
        {
            return (BigInteger.Zero,BigInteger.Zero,BigInteger.Zero);
        } else if (a == BigInteger.Zero)
        {
            return (b,BigInteger.Zero,BigInteger.One);
        } else if (b == BigInteger.Zero)
        {
            return (a,BigInteger.One,BigInteger.Zero);
        }

        // computing gcd with q's
        List<BigInteger> qs = new List<BigInteger>();
        BigInteger big = a > b ? a : b;
        BigInteger small = a < b ? a : b;
        BigInteger tmp;
        while ((tmp = big % small) != BigInteger.Zero)
        {
            qs.Add(big / small);
            big = small;
            small = tmp;
        }
        BigInteger gcd = small;

        // determining u and v
        BigInteger u = BigInteger.Zero;
        BigInteger v = BigInteger.One;
        for (int i = qs.Count() - 1; i >= 0 ; --i)
        {
            tmp = u;
            u = v;
            v = tmp - qs[i] * v;
        }

        return a > b ? (gcd,u,v) : (gcd,v,u);
    }

    extension(BigInteger a) {

        /// <summary>
        /// Calculates this (mod n).
        /// </summary>
        /// <param name="n">The modulus n.</param>
        /// <returns>this (mod n)/returns>
        public BigInteger Mod(BigInteger n) {
            if (n < 2) throw new ArgumentOutOfRangeException(nameof(n), "Modulus must be greater than 1.");

            var result = a % n;
            if (result < 0) return result + n;
            return result;
        }

        /// <summary>
        /// Calculates this + b (mod n).
        /// </summary>
        /// <param name="b">The number to add.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this + b (mod n)/returns>
        public BigInteger ModAdd(BigInteger b, BigInteger n) {
            return Mod(Mod(a, n) + Mod(b, n), n);
        }

        /// <summary>
        /// Calculates this - b (mod n).
        /// </summary>
        /// <param name="b">The number to subtract.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this - b (mod n)/returns>
        public BigInteger ModSubstract(BigInteger b, BigInteger n) {
            return Mod(Mod(a, n) + Mod(-b, n), n);
        }

        /// <summary>
        /// Calculates this * b (mod n).
        /// </summary>
        /// <param name="b">The number to multiply.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this * b (mod n)/returns>
        public BigInteger ModMultiply(BigInteger b, BigInteger n) {
            return Mod(Mod(a, n) * Mod(b, n), n);
        }

        /// <summary>
        /// Calculates this^-1 (mod n).
        /// </summary>
        /// <param name="n">The modulus n.</param>
        /// <returns>this^-1 (mod n)/returns>
        /// <remarks>
        /// You must implement this using <see cref="ExtendedEuclidean"/>.
        /// </remarks>
        public BigInteger ModInverse(BigInteger n) {
            if (a == BigInteger.Zero)
            {
                throw new ArgumentOutOfRangeException();
            }

            var (gcd, s, _) = ExtendedEuclidean(a, n);
            
            if (gcd != BigInteger.One)
            {
                throw new ArgumentException();
            }

            return s.Mod(n);
        }

        /// <summary>
        /// Calculates this / b (mod n).
        /// </summary>
        /// <param name="b">The number to divide by.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this / b (mod n)/returns>
        public BigInteger ModDivide(BigInteger b, BigInteger n) {
            return a * b.ModInverse(n) % n;
        }

        /// <summary>
        /// Computes this^e (mod n).
        /// </summary>
        /// <param name="e">The exponent (must be non-negative).</param>
        /// <param name="n">The modulus (must be positive).</param>
        /// <returns>The result of b^e (mod n).</returns>
        /// <remarks>
        /// You must implement this function efficiently.
        /// At most, you may use <see cref="ModMultiply" /> Ceiling(log2(base)) + #bits_set(exponent)) times.
        /// You are only allowed a single <see cref="BigInteger"/> for local variables.
        /// </remarks>
        public BigInteger ModExp(BigInteger e, BigInteger n) {
            BigInteger output = BigInteger.One;
            if (e.Sign < BigInteger.Zero)
            {
                e *= new BigInteger(-1);
                a = a.ModInverse(n);
            }

            while (e > BigInteger.Zero)
            {
                if ((e & BigInteger.One) != BigInteger.Zero)
                {
                    output = output.ModMultiply(a, n);
                }
                a = a.ModMultiply(a, n);
                e >>= 1;
            }
            return output;
        }

    }
}