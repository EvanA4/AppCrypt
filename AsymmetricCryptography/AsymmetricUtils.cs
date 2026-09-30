using System.Numerics;
using System.Security.Cryptography;
using MathUtils;

namespace AsymmetricCryptography;

internal static class AsymmetricUtils {

    extension(BigInteger) {
        /// <summary>
        /// Converts a big-endian, unsigned byte span into a <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="bytes">The bytes to interpret, in big-endian, unsigned order.</param>
        /// <returns>The resulting non-negative <see cref="BigInteger"/> value.</returns>
        public static BigInteger FromByteArray(ReadOnlySpan<byte> bytes) {
            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// Generates a cryptographically secure random <see cref="BigInteger"/> in the range 
        /// [<paramref name="min"/>, <paramref name="max"/>], using rejection sampling to avoid modulo bias.
        /// </summary>
        /// <param name="min">The inclusive lower bound.</param>
        /// <param name="max">The inclusive upper bound.</param>
        /// <returns>
        /// A uniformly distributed random value between <paramref name="min"/> and 
        /// <paramref name="max"/>, inclusive.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="min"/> is not less than <paramref name="max"/>.
        /// </exception>
        /// <remarks>Do not use the modulus operation at all in your implementation.</remarks>
        public static BigInteger GetRandom(BigInteger min, BigInteger max) {
            // Validate inputs
            if (min < 0 || max < 0 || min > max) throw new ArgumentException();

            // Get difference's mask and byte array
            BigInteger diff = max - min;
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

                if (num <= diff)
                    return num + min;
            }
        }
    }

    extension(BigInteger x) {

        /// <summary>
        /// Converts this non-negative <see cref="BigInteger"/> to a fixed-length, big-endian,
        /// unsigned byte array,
        /// left-padding with zero bytes as needed.
        /// </summary>
        /// <param name="byteCount">The exact length, in bytes, of the resulting array.</param>
        /// <returns>
        /// A big-endian, unsigned byte representation of the value, <paramref name="byteCount"/> bytes long.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the value is negative, or cannot fit within <paramref name="byteCount"/> bytes,
        /// or the conversion otherwise fails.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when <paramref name="byteCount"/> is not greater than 0.
        /// </exception>
        public byte[] ToByteArray(int byteCount) {
            if (x.Sign < 0)
                throw new InvalidOperationException("Value must be non-negative.");
            if (byteCount <= 0)
                throw new ArgumentOutOfRangeException(nameof(byteCount), "Byte length must be greater than 0.");

            // Get the number of bytes needed
            var needed = x.IsZero ? 0 : x.GetByteCount(isUnsigned: true);
            if (needed > byteCount)
                throw new InvalidOperationException("Value cannot fit within the desired byte length.");

            var bytes = new byte[byteCount];
            if (needed > 0)
                if (!x.TryWriteBytes(bytes.AsSpan(byteCount - needed), out var written, isUnsigned: true, isBigEndian: true) || written != needed)
                    throw new InvalidOperationException("Conversion failed.");

            return bytes;
        }
    }

    extension(PrimeUtils) {

        /// <summary>
        /// Generates a random safe prime of the requested bit length.
        /// </summary>
        /// <param name="bitLength">The desired bit length of the safe prime.
        /// <returns>
        /// A tuple containing the safe prime <c>p</c> and the prime <c>q</c> where <c>p = 2q + 1</c>.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when <paramref name="bitLength"/> is 4 or less.
        /// </exception>
        public static (BigInteger p, BigInteger q) GetRandomSafePrime(int bitLength) {
            if (bitLength <= 4) throw new ArgumentOutOfRangeException();

            while (true)
            {
                BigInteger candidateP = PrimeUtils.GetRandomPrime(bitLength);
                BigInteger candidateQ = (candidateP - BigInteger.One) >> 1;
                if (PrimeUtils.IsProbablePrime(candidateQ)) return (candidateP, candidateQ);
            }
        }

    }

}