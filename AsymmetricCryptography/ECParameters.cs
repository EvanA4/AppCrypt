using System.Globalization;
using System.Numerics;
using MathUtils;

namespace AsymmetricCryptography;

/// <summary>
/// Domain parameters for the NIST prime curves (FIPS 186-5 / SP 800-186).
///
/// <para>
/// Every curve here is a short-Weierstrass curve y^2 = x^3 + ax + b over F_p with
/// a = p - 3, cofactor 1 (so the group order IS the prime <c>Order</c>, and there is
/// no small-subgroup structure to worry about), and a p chosen as a generalized
/// Mersenne prime so reduction can be done with shifts and adds instead of division.
/// </para>
///
/// <para>
/// Pair each curve with a hash of comparable strength: P-256 with SHA-256, P-384 with
/// SHA-384, P-521 with SHA-512. Using SHA-256 with P-521 caps the signature at 128-bit
/// collision resistance and wastes most of the curve.
/// </para>
/// </summary>
public static class ECParameters {

    public record struct Parameters(ECCurve Curve, ECPoint Generator, BigInteger Order);

    /// <summary>
    /// NIST P-256 (secp256r1, prime256v1). p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
    /// ~128-bit security. The default choice; pair with SHA-256.
    /// </summary>
    public static Parameters NISTP256 { get => _nistP256.Value; }
    private static readonly Lazy<Parameters> _nistP256 = new Lazy<Parameters>(() => Create(
            p: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            a: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            b: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            generatorX: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            generatorY: "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            order: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    );

    /// <summary>
    /// NIST P-384 (secp384r1). p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
    /// ~192-bit security. Pair with SHA-384.
    /// </summary>
    public static Parameters NISTP384 { get => _nistP384.Value; }
    private static readonly Lazy<Parameters> _nistP384 = new Lazy<Parameters>(() => Create(
            p: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            a: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            b: "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            generatorX: "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            generatorY: "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            order: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973")
    );

    /// <summary>
    /// NIST P-521 (secp521r1). p = 2^521 - 1, an actual Mersenne prime.
    /// ~256-bit security. Pair with SHA-512.
    ///
    /// <para>
    /// Note the 521, not 512: the field is 521 bits, so a scalar occupies 66 bytes and
    /// the top byte holds only a single significant bit. Anything that assumes a whole
    /// number of 32- or 64-bit words, or that a coordinate is a power-of-two byte count,
    /// breaks here. That makes it the useful curve to test size handling against.
    /// </para>
    /// </summary>
    public static Parameters NISTP521 { get => _nistP521.Value; }
    private static readonly Lazy<Parameters> _nistP521 = new Lazy<Parameters>(() => Create(
            p: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            a: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            b: "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            generatorX: "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            generatorY: "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            order: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")
    );

    /// <summary>
    /// Builds a parameter set from unsigned big-endian hex.
    ///
    /// <para>
    /// The "0" prefix is the point of this helper. <see cref="NumberStyles.HexNumber"/>
    /// parses two's complement, so a string whose leading nibble is 8-F comes back
    /// NEGATIVE -- and every one of these p, a, and order values starts with 0xF.
    /// Prefixing a zero nibble here means the constants above can be written exactly as
    /// they appear in FIPS 186-5, with no stray padding digit for a reader to
    /// second-guess, and no way to forget it on a newly added curve.
    /// </para>
    /// </summary>
    private static Parameters Create(string p, string a, string b,
                                     string generatorX, string generatorY, string order) {
        var curve = new ECCurve(Parse(a), Parse(b), Parse(p));
        var generator = curve.GetPoint(Parse(generatorX), Parse(generatorY));
        return new Parameters(curve, generator, Parse(order));
    }

    /// <summary>
    /// Parses a unsigned <see cref="BigInteger"/> from a hex string.
    /// </summary>
    /// <param name="hex">Hex string with the number.</param>
    /// <returns>An unsigned <see cref="BigInteger"/> derived from the hex string.</returns>
    private static BigInteger Parse(string hex) =>
        BigInteger.Parse("00" + hex, NumberStyles.HexNumber);

}
