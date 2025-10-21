// Windows: BCryptGenRandom
#pragma comment(lib, "bcrypt.lib")

#include "project_aes_win.h"

#include <stddef.h>  
#include <string.h>   
#include <stdio.h>    
#include <stdlib.h>   

// Windows
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

// --- AES ---

// S-box (256)
static const byte sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// inv S-box
static const byte inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon
static const word RCON[14] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000,
    0xab000000, 0x4d000000
};

// ---  AES (static) ---

// SubBytes
static void aes_subbytes(byte state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = sbox[state[row][col]];
        }
    }
}

// inv SubBytes
static void aes_inv_subbytes(byte state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = inv_sbox[state[row][col]];
        }
    }
}

// ShiftRows
static void aes_shiftrows(byte state[4][4]) {
    byte temp;
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// inv ShiftRows
static void aes_inv_shiftrows(byte state[4][4]) {
    byte temp;
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

static byte xtime(byte x) {
    // x*2 mod 0x11b
    return (x << 1) ^ ((x >> 7) ? 0x1b : 0x00);
}

static byte gmul(byte a, byte b) {
    byte p = 0;
    byte counter;
    for (counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
            p ^= a;
        }
        byte hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set != 0) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return p;
}

// MixColumns
static void aes_mixcolumns(byte state[4][4]) {
    for (int col = 0; col < 4; col++) {
        byte a0 = state[0][col];
        byte a1 = state[1][col];
        byte a2 = state[2][col];
        byte a3 = state[3][col];
        state[0][col] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        state[1][col] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        state[2][col] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        state[3][col] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

// inv MixColumns
static void aes_inv_mixcolumns(byte state[4][4]) {
    for (int col = 0; col < 4; col++) {
        byte a0 = state[0][col];
        byte a1 = state[1][col];
        byte a2 = state[2][col];
        byte a3 = state[3][col];
        state[0][col] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        state[1][col] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        state[2][col] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        state[3][col] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

// AddRoundKey
static void aes_addroundkey(const word* w, byte state[4][4], int round) {
    for (int col = 0; col < 4; col++) {
        word k = w[round * 4 + col];
        state[0][col] ^= (byte)(k >> 24);
        state[1][col] ^= (byte)(k >> 16);
        state[2][col] ^= (byte)(k >> 8);
        state[3][col] ^= (byte)k;
    }
}

// RotWord
static word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

// SubWord
static word SubWord(word w) {
    return (sbox[(w >> 24) & 0xFF] << 24) |
        (sbox[(w >> 16) & 0xFF] << 16) |
        (sbox[(w >> 8) & 0xFF] << 8) |
        (sbox[w & 0xFF]);
}

static void construct_counter_block(byte counter_block[AES_BLOCK_SIZE], const byte* nonce, uint64_t counter) {
    memcpy(counter_block, nonce, 8);
    for (int i = 0; i < 8; i++) {
        counter_block[8 + i] = (byte)((counter >> (8 * i)) & 0xFF);
    }
}

// --- API ---

int aes_keyexpansion(const byte* key, word* w, size_t key_len) {
    int Nk = (int)key_len / 4;           
    int Nr;                               
    if (Nk == AES_NK_128) Nr = AES_NR_128;
    else if (Nk == AES_NK_192) Nr = AES_NR_192;
    else if (Nk == AES_NK_256) Nr = AES_NR_256;
    else {
        fprintf(stderr, "Unsupported key length: %zu bytes (Nk=%d). Must be 16, 24, or 32 bytes.\n", key_len, Nk);
        return -1;
    }

    for (int i = 0; i < Nk; i++) {
        w[i] = ((word)key[4 * i] << 24) | ((word)key[4 * i + 1] << 16) |
            ((word)key[4 * i + 2] << 8) | (word)key[4 * i + 3];
    }

    for (int i = Nk; i < 4 * (Nr + 1); i++) {
        word temp = w[i - 1];
        if (i % Nk == 0) {
            // RotWord -> SubWord -> RCON XOR
            temp = SubWord(RotWord(temp)) ^ RCON[(i / Nk) - 1];
        }
        else if (Nk > 6 && (i % Nk == 4)) {
            temp = SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
    return Nr;
}

// AES
void aes_encrypt(byte input[AES_BLOCK_SIZE], byte output[AES_BLOCK_SIZE], const word* w, int Nr) {
    byte state[4][4];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) state[i % 4][i / 4] = input[i];

    aes_addroundkey(w, state, 0);

    for (int round = 1; round < Nr; round++) {
        aes_subbytes(state);
        aes_shiftrows(state);
        aes_mixcolumns(state);
        aes_addroundkey(w, state, round);
    }

    aes_subbytes(state);
    aes_shiftrows(state);
    aes_addroundkey(w, state, Nr);

    for (int i = 0; i < AES_BLOCK_SIZE; i++) output[i] = state[i % 4][i / 4];
}


void aes_decrypt(byte input[AES_BLOCK_SIZE], byte output[AES_BLOCK_SIZE], const word* w, int Nr) {
    byte state[4][4];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) state[i % 4][i / 4] = input[i];

    aes_addroundkey(w, state, Nr);

    for (int round = Nr - 1; round >= 1; round--) {
        aes_inv_shiftrows(state);
        aes_inv_subbytes(state);
        aes_addroundkey(w, state, round);
        aes_inv_mixcolumns(state);
    }

    aes_inv_shiftrows(state);
    aes_inv_subbytes(state);
    aes_addroundkey(w, state, 0); 

    for (int i = 0; i < AES_BLOCK_SIZE; i++) output[i] = state[i % 4][i / 4];
}

// CTR
void AES_CTR(const byte* input, byte* output, size_t length,
    const byte* key, const byte* nonce, size_t key_len) {
    word round_keys[60];
    byte counter_block[AES_BLOCK_SIZE];
    byte keystream[AES_BLOCK_SIZE];
    uint64_t counter = 0;

    int Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return; 

    size_t block_count = (length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    for (size_t i = 0; i < block_count; i++) {
        size_t offset = i * AES_BLOCK_SIZE;
        size_t block_len = (length - offset >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (length - offset);

        construct_counter_block(counter_block, nonce, counter);

        aes_encrypt(counter_block, keystream, round_keys, Nr);

        for (size_t j = 0; j < block_len; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }
        counter++;
    }
}

// ECB
void AES_ECB(const byte* input, byte* output, size_t length,
    const byte* key, size_t key_len, int encrypt) {
    word round_keys[60];

    int Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return; 
    size_t block_count = length / AES_BLOCK_SIZE;
    for (size_t i = 0; i < block_count; i++) {
        size_t offset = i * AES_BLOCK_SIZE;
        if (encrypt) {
            aes_encrypt((byte*)(input + offset), output + offset, round_keys, Nr);
        }
        else {
            aes_decrypt((byte*)(input + offset), output + offset, round_keys, Nr);
        }
    }

    size_t remaining = length % AES_BLOCK_SIZE;
    if (remaining > 0) {
        memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
    }
}

// CBC 
void AES_CBC(const byte* input, byte* output, size_t length,
    const byte* key, const byte* iv, size_t key_len, int encrypt) {
    word round_keys[60];
    byte block[AES_BLOCK_SIZE];
    byte prev_block[AES_BLOCK_SIZE];
    byte current_block[AES_BLOCK_SIZE];

    int Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return; 

    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    size_t block_count = length / AES_BLOCK_SIZE;

    if (encrypt) {
        for (size_t i = 0; i < block_count; i++) {
            size_t offset = i * AES_BLOCK_SIZE;

            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                block[j] = input[offset + j] ^ prev_block[j];
            }
            aes_encrypt(block, output + offset, round_keys, Nr);
            memcpy(prev_block, output + offset, AES_BLOCK_SIZE);
        }
    }
    else {
        for (size_t i = 0; i < block_count; i++) {
            size_t offset = i * AES_BLOCK_SIZE;

            memcpy(current_block, input + offset, AES_BLOCK_SIZE);

            aes_decrypt((byte*)(input + offset), block, round_keys, Nr);

            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                output[offset + j] = block[j] ^ prev_block[j];
            }

            memcpy(prev_block, current_block, AES_BLOCK_SIZE);
        }
    }

    size_t remaining = length % AES_BLOCK_SIZE;
    if (remaining > 0) {
        memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
    }
}

// --- SHA-256 ---

//static const uint32_t sha256_k[64] = {
//}

//static void sha256_transform(){
//}

//void sha256_init(){
//}

//void sha256_update(){
//}

//void sha256_final(){
//}

//void sha256(){
//}



int generate_secure_key(byte* key, size_t key_len) {
#ifdef _WIN32
    // Windows: BCryptGenRandom
    NTSTATUS status = BCryptGenRandom(NULL, key, (ULONG)key_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGenRandom failed with status: 0x%x\n", (unsigned int)status);
        return -1;
    }
#else
    FILE* fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("Failed to open /dev/urandom");
        return -1;
    }
    if (fread(key, 1, key_len, fp) != key_len) {
        fprintf(stderr, "Failed to read %zu bytes from /dev/urandom\n", key_len);
        fclose(fp);
        return -1;
    }
    fclose(fp);
#endif
    return 0;
}
