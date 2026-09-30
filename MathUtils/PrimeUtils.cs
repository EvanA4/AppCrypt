using System.Numerics;
using System.Security.Cryptography;

namespace MathUtils;

/// <summary>
/// Utility methods for working with primes.
/// </summary>
public static class PrimeUtils {

    /// <summary>
    /// Get a random prime number.
    /// </summary>
    /// <param name="bits">Number of bits in the prime number.</param>
    /// <returns>Prime number on the given number of bits.</returns>
    public static BigInteger GetRandomPrime(int bits) {
        if (bits <= 2)
        {
            throw new ArgumentOutOfRangeException();
        }

        BigInteger num = GetRandomBigInteger(
            BigInteger.One << (bits - 1),
            BigInteger.One << bits
        );

        while (!IsProbablePrime(num))
        {
            num = GetRandomBigInteger(
                BigInteger.One << (bits - 1),
                BigInteger.One << bits
            );
        }

        return num;
    }

    /// <summary>
    /// Generates a random BigInteger within a specified range (exclusive).
    /// </summary>
    /// <param name="lower">Minimum value of returned BigInteger.</param>
    /// <param name="lower">Minimum value of returned BigInteger.</param>
    /// <returns>Random a BigInteger in range [lower, upper].</returns>
    private static BigInteger GetRandomBigInteger(BigInteger lower, BigInteger upper)
    {
        // Validate inputs
        if (lower <= 0 || upper <= 0 || lower >= upper)
            throw new ArgumentOutOfRangeException();

        // Get difference's mask and byte array
        BigInteger diff = upper - lower;
        byte[] bytes = diff.ToByteArray(
            isUnsigned: true,
            isBigEndian: true);
        BigInteger mask = (BigInteger.One << (int) diff.GetBitLength()) - BigInteger.One;

        // Randomly generate number and check if smaller than difference
        while (true)
        {
            RandomNumberGenerator.Fill(bytes);
            BigInteger num = new BigInteger(
                bytes,
                isUnsigned: true,
                isBigEndian: false);
            num &= mask;

            if (num < diff)
                return num + lower;
        }
    }

    /// <summary>
    /// Tests whether a number is probably prime using the Miller-Rabin primality test.
    /// </summary>
    /// <param name="n">The number to test (must be greater than 1).</param>
    /// <param name="rounds">
    /// The number of witness rounds. Higher values reduce the probability of a false
    /// positive. 40 rounds gives a false positive probability of at most 2^(-80).
    /// </param>
    /// <returns>
    /// False if n is definitely composite; true if n is probably prime.
    /// </returns>
    public static bool IsProbablePrime(BigInteger n, int rounds = 40) {
        if (n == new BigInteger(2) || n == new BigInteger(3)) // awkward edge cases for int generation
        {
            return true;
        } else if (n < new BigInteger(2))
        {
            return false;
        }

        BigInteger s = BigInteger.One;
        BigInteger d = n - BigInteger.One;
        while (d.IsEven)
        {
            s++;
            d /= new BigInteger(2);
        }

        for (int k = 0; k < rounds; k++)
        {
            BigInteger a = GetRandomBigInteger(new BigInteger(2), n - BigInteger.One);
            bool probablyPrime = false;
            BigInteger x = a.ModExp(d, n);
            if (x == BigInteger.One || x == (n - BigInteger.One))
                probablyPrime = true;
            
            for (int i = 1; !probablyPrime && (i < s); i++)
            {
                x = x.ModMultiply(x, n);
                if (x == (n - BigInteger.One))
                {
                    probablyPrime = true;
                }
            }
            
            if (!probablyPrime)
                return false;
        }
        
        return true;
    }

}