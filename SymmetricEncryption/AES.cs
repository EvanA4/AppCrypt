using MathUtils;
using static MathUtils.GFUtils;

namespace SymmetricEncryption;

/// <summary>
/// Supported BlockModes for AES.
/// </summary>
/// </remarks>
public enum BlockMode {
    /// <summary>
    /// Electronic Codebook.
    ECB,

    /// <summary>
    /// Cipher Block Chaining.
    CBC,

    /// <summary>
    /// Counter mode.
    CTR
}

/// <summary>
/// AES block cipher.
/// </summary>
/// <remarks>
/// Implement this class based on <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf">FIPS 197</a>
/// </remarks>
public sealed class AES {

    #region Constant values

    /// <summary>
    /// The AES block size in bytes.
    /// </summary>
    /// <remarks>Set the correct block size.</remark>
    internal const int BlockSize = 16;

    /// <summary>
    /// The AES substitution box (FIPS 197, Figure 7).
    /// </summary>
    internal static readonly byte[] SBox = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    ];

    /// <summary>
    /// The inverse AES substitution box (FIPS 197, Figure 14).
    /// </summary>
    internal static readonly byte[] InvSBox = [
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    ];

    /// <summary>
    /// The table of round constants, Table 5.
    /// </summary>
    internal static readonly byte[] rcon = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ];

    #endregion

    #region Variables storing shared state as AES executes

    /// <summary>
    /// The expanded key schedule.
    /// </summary>
    /// <remark>Do not change the visibility or name of this field. It is needed by the autograder.</remark>
    internal readonly byte[] w;

    /// <summary>
    /// The key length.
    /// </summary>
    /// <remark>Do not change the visibility or name of this field. It is needed by the autograder.</remark>
    internal readonly int Nk;

    /// <summary>
    /// The number of cipher rounds.
    /// </summary>
    /// <remark>Do not change the visibility or name of this field. It is needed by the autograder.</remark>
    internal readonly int Nr;

    /// <summary>
    /// The block size.
    /// </summary>
    internal readonly int Nb = 4;

    /// <summary>
    /// The internal state when encrypting or decrypting a block.
    /// </summary>
    /// <remark>Do not change the visibility or name of this field. It is needed by the autograder.</remark>
    internal readonly byte[] state;

    #endregion

    #region AES cipher

    /// <summary>
    /// Creates an AES object with associated key.
    /// </summary>
    /// <param name="key">Key to use for encryption and decryption</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="key"/> is not an appropriate length.
    /// </exception>
    public AES(ReadOnlySpan<byte> key) {
        switch (key.Length)
        {
            case 16:
                Nr = 10;
                break;
            case 24:
                Nr = 12;
                break;
            case 32:
                Nr = 14;
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    "AES keys must be 4, 6, or 8 words long"
                );
        }
        Nk = key.Length / Nb;
        w = new byte[4 * Nb * (Nr + 1)];
        state = new byte[4 * Nb];
        KeyExpansion(key);
    }

    /// <summary>
    /// Expands the cipher key into the round key schedule.
    /// </summary>
    /// <param name="key">The cipher key.</param>
    internal void KeyExpansion(ReadOnlySpan<byte> key) {
        int i = 0;
        while (i <= Nk - 1)
        {
            for (int j = 0; j < 4; ++j) w[4*i+j] = key[4*i+j]; 
            ++i;
        }

        byte[] temp = new byte[4];
        while (i <= 4*Nr + 3)
        {
            for (int j = 0; j < 4; ++j) temp[j] = w[4*(i-1)+j]; 
            if (i % Nk == 0)
            {
                // rotword
                byte tempByte = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = tempByte;
                // subword
                for (int j = 0; j < 4; ++j) temp[j] = SBox[temp[j]];
                // xor w rcon
                temp[0] ^= rcon[i / Nk - 1];
            
            } else if (Nk > 6 && i % Nk == 4)
            {
                // subword
                for (int j = 0; j < 4; ++j) temp[j] = SBox[temp[j]];
            }
            // w[i] = w[i-Nk] xor temp
            for (int j = 0; j < 4; ++j) w[i*4+j] = (byte) (w[(i-Nk)*4+j] ^ temp[j]);
            ++i;
        }
    }

    /// <summary>
    /// Enciphers a single block.
    /// </summary>
    /// <param name="input">The plaintext block.</param>
    /// <param name="output">The ciphertext block.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when input or output are not properly sized.
    /// </exception>
    internal void Cipher(ReadOnlySpan<byte> input, Span<byte> output) {
        // move input into state
        for (int i = 0; i < BlockSize; ++i) state[i] = input[i];

        // actual encryption of block
        AddRoundKey(w.AsSpan(0, BlockSize));
        for (int round = 1; round <= Nr - 1; ++round)
        {
            SubBytes();
            ShiftRows();
            MixColumns();
            AddRoundKey(w.AsSpan(BlockSize*round, BlockSize));
        }
        SubBytes();
        ShiftRows();
        AddRoundKey(w.AsSpan(BlockSize*Nr, BlockSize));
        for (int i = 0; i < BlockSize; ++i) output[i] = state[i];
    }

    /// <summary>
    /// Deciphers a single block.
    /// </summary>
    /// <param name="input">The plaintext block.</param>
    /// <param name="output">The ciphertext block.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when input or output are not properly sized.
    /// </exception>
    internal void InvCipher(ReadOnlySpan<byte> input, Span<byte> output) {
        // move input into state
        for (int i = 0; i < BlockSize; ++i) state[i] = input[i];

        // actual encryption of block
        AddRoundKey(w.AsSpan(BlockSize*Nr, BlockSize));
        for (int round = 1; round <= Nr - 1; ++round)
        {
            InvShiftRows();
            InvSubBytes();
            AddRoundKey(w.AsSpan(BlockSize*(Nr-round), BlockSize));
            InvMixColumns();
        }
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(w.AsSpan(0, BlockSize));
        for (int i = 0; i < BlockSize; ++i) output[i] = state[i];
    }

    /// <summary>
    /// Add the round key to the state.
    /// </summary>
    /// <param name="roundKey">The portion of the round key to combine into the state.</param>
    internal void AddRoundKey(ReadOnlySpan<byte> roundKey) {
        for (int i = 0; i < BlockSize; ++i) state[i] ^= roundKey[i];
    }

    /// <summary>
    /// Apply the SubBytes algorithm to the state.
    /// </summary>
    internal void SubBytes() {
        for (int i = 0; i < BlockSize; ++i) state[i] = SBox[state[i]];
    }

    /// <summary>
    /// Apply the InvSubBytes algorithm to the state.
    /// </summary>
    internal void InvSubBytes() {
        for (int i = 0; i < BlockSize; ++i) state[i] = InvSBox[state[i]];
    }

    /// <summary>
    /// Apply the ShiftRows algorithm to the state.
    /// </summary>
    internal void ShiftRows() {
        byte[] original = new byte[BlockSize];
        for (int i = 0; i < BlockSize; ++i) original[i] = state[i];

        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                int to = 4 * j + i;
                int from = (j + i) % 4 * 4 + i;
                state[to] = original[from];
            }
        }
    }

    /// <summary>
    /// Apply the InvShiftRows algorithm to the state.
    /// </summary>
    internal void InvShiftRows() {
        byte[] original = new byte[BlockSize];
        for (int i = 0; i < BlockSize; ++i) original[i] = state[i];

        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                int to = 4 * j + i;
                int from = (j + 4 - i) % 4 * 4 + i;
                state[to] = original[from];
            }
        }
    }

    /// <summary>
    /// Apply the MixColumns algorithm to the state.
    /// </summary>
    internal void MixColumns() {
        for (int i = 0; i < 4; ++i)
        {
            byte[] columnWord = new byte[4];
            byte[] writeBack = new byte[4];
            for (int j = 0; j < 4; ++j) columnWord[j] = state[4*i+j]; // grab col for each row
            writeBack[0] = (byte) (GFUtils.GFMultiply(2, columnWord[0]) ^ GFUtils.GFMultiply(3, columnWord[1]) ^ columnWord[2] ^ columnWord[3]);
            writeBack[1] = (byte) (columnWord[0] ^ GFUtils.GFMultiply(2, columnWord[1]) ^ GFUtils.GFMultiply(3, columnWord[2]) ^ columnWord[3]);
            writeBack[2] = (byte) (columnWord[0] ^ columnWord[1] ^ GFUtils.GFMultiply(2, columnWord[2]) ^ GFUtils.GFMultiply(3, columnWord[3]));
            writeBack[3] = (byte) (GFUtils.GFMultiply(3, columnWord[0]) ^ columnWord[1] ^ columnWord[2] ^ GFUtils.GFMultiply(2, columnWord[3]));
            for (int j = 0; j < 4; ++j) state[4*i+j] = writeBack[j]; // set col for each row
        }
    }

    /// <summary>
    /// Apply the InvMixColumns algorithm to the state.
    /// </summary>
    internal void InvMixColumns() {
        for (int i = 0; i < 4; ++i)
        {
            byte[] columnWord = new byte[4];
            byte[] writeBack = new byte[4];
            for (int j = 0; j < 4; ++j) columnWord[j] = state[4*i+j]; // grab col for each row
            writeBack[0] = (byte) (GFUtils.GFMultiply(0x0e, columnWord[0]) ^ GFUtils.GFMultiply(0x0b, columnWord[1]) ^ GFUtils.GFMultiply(0x0d, columnWord[2]) ^ GFUtils.GFMultiply(0x09, columnWord[3]));
            writeBack[1] = (byte) (GFUtils.GFMultiply(0x09, columnWord[0]) ^ GFUtils.GFMultiply(0x0e, columnWord[1]) ^ GFUtils.GFMultiply(0x0b, columnWord[2]) ^ GFUtils.GFMultiply(0x0d, columnWord[3]));
            writeBack[2] = (byte) (GFUtils.GFMultiply(0x0d, columnWord[0]) ^ GFUtils.GFMultiply(0x09, columnWord[1]) ^ GFUtils.GFMultiply(0x0e, columnWord[2]) ^ GFUtils.GFMultiply(0x0b, columnWord[3]));
            writeBack[3] = (byte) (GFUtils.GFMultiply(0x0b, columnWord[0]) ^ GFUtils.GFMultiply(0x0d, columnWord[1]) ^ GFUtils.GFMultiply(0x09, columnWord[2]) ^ GFUtils.GFMultiply(0x0e, columnWord[3]));
            for (int j = 0; j < 4; ++j) state[4*i+j] = writeBack[j]; // set col for each row
        }
    }

    #endregion

    #region Encryption/decryption methods

    /// <summary>
    /// Encrypts a message using the requested block cipher mode.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="mode">The block cipher mode to apply.</param>
    /// <param name="ivOrCounter">
    /// The IV for <see cref="BlockMode.CBC"/> or initial counter for
    /// <see cref="BlockMode.CTR"/>. Ignored for <see cref="BlockMode.ECB"/>.
    /// </param>
    /// <returns>The ciphertext.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="ivOrCounter"/> is not the correct length.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="mode"/> is not a recognized <see cref="BlockMode"/>.
    /// </exception>
    public byte[] Encrypt(
        ReadOnlySpan<byte> plaintext, BlockMode mode, ReadOnlySpan<byte> ivOrCounter = default) =>
       mode switch {
           BlockMode.ECB => EncryptECB(plaintext),
           BlockMode.CBC => EncryptCBC(plaintext, ivOrCounter),
           BlockMode.CTR => ApplyCTR(plaintext, ivOrCounter),
           _ => throw new ArgumentOutOfRangeException(nameof(mode), "Unsupported or invalid mode.")
       };

    /// <summary>
    /// Decrypts a message using the requested block cipher mode.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="mode">The block cipher mode to apply.</param>
    /// <param name="ivOrCounter">
    /// The IV for <see cref="BlockMode.CBC"/> or the initial counter for
    /// <see cref="BlockMode.CTR"/>. Ignored for <see cref="BlockMode.ECB"/>.
    /// </param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="ivOrCounter"/> is not the correct length.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="mode"/> is not a recognized <see cref="BlockMode"/>.
    /// </exception>
    public byte[] Decrypt(
        ReadOnlySpan<byte> ciphertext, BlockMode mode, ReadOnlySpan<byte> ivOrCounter = default) =>
        mode switch {
            BlockMode.ECB => DecryptECB(ciphertext),
            BlockMode.CBC => DecryptCBC(ciphertext, ivOrCounter),
            BlockMode.CTR => ApplyCTR(ciphertext, ivOrCounter),
            _ => throw new ArgumentOutOfRangeException(nameof(mode), "Unsupported or invalid mode.")
        };

    /// <summary>
    /// Encrypts a message in ECB mode.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <returns>The ciphertext.</returns>
    internal byte[] EncryptECB(ReadOnlySpan<byte> plaintext) {
        // convert to block-friendly byte array
        int numPadding = BlockSize - plaintext.Length % BlockSize;
        byte[] toEncrypt = new byte[plaintext.Length + numPadding];
        for (int i = 0; i < toEncrypt.Length; ++i)
        {
            if (i < plaintext.Length) toEncrypt[i] = plaintext[i];
            else toEncrypt[i] = (byte) numPadding;
        } 

        // actually encrypt
        ReadOnlySpan<byte> plainSpan = new ReadOnlySpan<byte>(toEncrypt);
        Span<byte> cipherSpan = new Span<byte>(new byte[plaintext.Length + numPadding]);
        for (int i = 0; i < toEncrypt.Length; i += BlockSize)
        {
            Cipher(plainSpan.Slice(i, BlockSize), cipherSpan.Slice(i, BlockSize));
        }
        return cipherSpan.ToArray();
    }

    /// <summary>
    /// Decrypts an ECB ciphertext.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the ciphertext is not block aligned or the recovered padding is invalid.
    /// </exception>
    internal byte[] DecryptECB(ReadOnlySpan<byte> ciphertext) {
        if (ciphertext.IsEmpty || ciphertext.Length % BlockSize != 0)
        {
            throw new ArgumentException("Invalid IV or ciphertext size.");
        }

        Span<byte> plainSpan = new Span<byte>(new byte[ciphertext.Length]);
        for (int i = 0; i < ciphertext.Length; i += BlockSize)
        {
            InvCipher(ciphertext.Slice(i, BlockSize), plainSpan.Slice(i, BlockSize));
        }
        int numPadding = plainSpan[plainSpan.Length - 1];
        if (numPadding < 1  || numPadding > BlockSize) {
            throw new ArgumentException("Invalid padding.");
        }
        for (int i = 0; i < numPadding; ++i) {
            if (plainSpan[plainSpan.Length - 1 - i] != numPadding) {
                throw new ArgumentException("Invalid padding.");                
            }
        }
        return plainSpan.Slice(0, plainSpan.Length - numPadding).ToArray();
    }

    /// <summary>
    /// Encrypts a message in CBC mode.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>The ciphertext.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="iv"/> is not 16 bytes.</exception>
    internal byte[] EncryptCBC(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv) {
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException("Invalid IV size.");
        }

        // convert to block-friendly byte array
        int numPadding = BlockSize - plaintext.Length % BlockSize;
        byte[] toEncrypt = new byte[plaintext.Length + numPadding];
        byte[] toXOR = iv.ToArray();
        for (int i = 0; i < toEncrypt.Length; ++i)
        {
            if (i < plaintext.Length) toEncrypt[i] = plaintext[i];
            else toEncrypt[i] = (byte) numPadding;
        } 

        // actually encrypt
        Span<byte> plainSpan = new Span<byte>(toEncrypt);
        Span<byte> cipherSpan = new Span<byte>(new byte[plaintext.Length + numPadding]);
        for (int i = 0; i < toEncrypt.Length; i += BlockSize)
        {
            for (int j = 0; j < BlockSize; ++j) plainSpan[i+j] ^= toXOR[j];
            Cipher(plainSpan.Slice(i, BlockSize), cipherSpan.Slice(i, BlockSize));
            toXOR = cipherSpan.Slice(i, BlockSize).ToArray();
        }
        return cipherSpan.ToArray();
    }

    /// <summary>
    /// Decrypts an CBC ciphertext.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="iv"/> is not 16 bytes. Also Thrown when the ciphertext
    /// is not block aligned or the recovered padding is invalid.
    /// </exception>
    internal byte[] DecryptCBC(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv) {
        if (ciphertext.IsEmpty || iv.Length != BlockSize || ciphertext.Length % BlockSize != 0)
        {
            throw new ArgumentException("Invalid IV or ciphertext size.");
        }

        // actually encrypt
        byte[] toXOR = iv.ToArray();
        Span<byte> plainSpan = new Span<byte>(new byte[ciphertext.Length]);
        for (int i = 0; i < ciphertext.Length; i += BlockSize)
        {
            InvCipher(ciphertext.Slice(i, BlockSize), plainSpan.Slice(i, BlockSize));
            for (int j = 0; j < BlockSize; ++j) plainSpan[i+j] ^= toXOR[j];
            toXOR = ciphertext.Slice(i, BlockSize).ToArray();
        }
        int numPadding = plainSpan[plainSpan.Length - 1];
        if (numPadding < 1  || numPadding > BlockSize) {
            throw new ArgumentException("Invalid padding.");
        }
        for (int i = 0; i < numPadding; ++i) {
            if (plainSpan[plainSpan.Length - 1 - i] != numPadding) {
                throw new ArgumentException("Invalid padding.");                
            }
        }
        return plainSpan.Slice(0, plainSpan.Length - numPadding).ToArray();
    }

    /// <summary>
    /// Encrypts or decrypts a message in CTR mode.
    /// </summary>
    /// <param name="input">The message to encrypt or ciphertext to decrypt.</param>
    /// <param name="counter">The initial counter value.</param>
    /// <returns>The ciphertext or decrypted plaintext.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="counter"/> is not 16 bytes.</exception>
    internal byte[] ApplyCTR(ReadOnlySpan<byte> input, ReadOnlySpan<byte> counter) {
        if (counter.Length != BlockSize)
        {
            throw new ArgumentException("Invalid IV size.");
        }

        // actually encrypt
        Span<byte> countable = new Span<byte>(counter.ToArray());
        Span<byte> toXOR = new Span<byte>(new byte[BlockSize]);
        byte[] cipherArr = new byte[input.Length];
        for (int i = 0; i < input.Length; i += BlockSize)
        {
            Cipher(countable, toXOR);
            for (int j = 0; j < BlockSize && i + j < input.Length; ++j) cipherArr[i+j] = (byte) (toXOR[j] ^ input[i+j]);

            // increment counter
            for (int j = BlockSize - 1; j >= 0; --j)
            {
                if (++countable[j] != 0) break;
            }
        }
        return cipherArr;
    }

    /// <summary>
    /// Appends PKCS#7 padding so the result is a whole number of blocks.
    /// </summary>
    /// <param name="data">The data to pad.</param>
    /// <returns>A new array containing the padded data.</returns>
    internal static byte[] AddPKCS7Padding(ReadOnlySpan<byte> data) {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Validates and removes PKCS#7 padding.
    /// </summary>
    /// <param name="data">The padded data.</param>
    /// <returns>A new array containing the data with its padding removed.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the data is not block aligned or the padding bytes are not well formed.
    /// </exception>
    internal static byte[] RemovePKCS7Padding(byte[] data) {
        throw new NotImplementedException();
    }

    #endregion

}
