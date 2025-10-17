#include "project_aes_ctr.h"

#include <stddef.h>   // size_t 타입 정의
#include <string.h>   // memcpy, memset 사용을 위해 포함
#include <stdio.h>    // fprintf, perror 사용을 위해 포함
#include <stdlib.h>   // malloc, free 사용을 위해 포함

// 프로젝트 헤더 파일에 정의된 타입:
// typedef uint8_t  byte;
// typedef uint32_t word;

// --- AES 상수 정의 (정적(static)으로 선언하여 외부에서 접근 불가하도록 캡슐화) ---

// AES에서 사용할 S-box (256바이트 테이블)
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

// AES에서 사용할 역 S-box
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

// Rcon 배열 (라운드 키 확장에서 사용)
static const word RCON[14] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000,
    0xab000000, 0x4d000000
};


// --- 내부 AES 라운드 함수 정의 (static) ---

// 바이트 치환 (SubBytes 단계)
static void aes_subbytes(byte state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = sbox[state[row][col]];
        }
    }
}

// 역 SubBytes
static void aes_inv_subbytes(byte state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = inv_sbox[state[row][col]];
        }
    }
}

// ShiftRows 단계
static void aes_shiftrows(byte state[4][4]) {
    byte temp;
    // 2행: 왼쪽으로 1칸 이동
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    // 3행: 왼쪽으로 2칸 이동
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    // 4행: 왼쪽으로 3칸 이동 (== 오른쪽으로 1칸 이동)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// 역 ShiftRows
static void aes_inv_shiftrows(byte state[4][4]) {
    byte temp;
    // 2행: 오른쪽으로 1칸 이동
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    // 3행: 오른쪽으로 2칸 이동
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    // 4행: 오른쪽으로 3칸 이동 (== 왼쪽으로 1칸 이동)
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// GF(2^8)에서 x*2 곱셈 함수
static byte xtime(byte x) {
    // x*2 mod 0x11b
    return (x << 1) ^ ((x >> 7) ? 0x1b : 0x00); 
}

// GF(2^8) 필드에서의 일반 곱셈 함수
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
            a ^= 0x1b; // 0x11b 다항식
        }
        b >>= 1;
    }
    return p;
}

// MixColumns 단계
static void aes_mixcolumns(byte state[4][4]) {
    for (int col = 0; col < 4; col++) {
        byte a0 = state[0][col];
        byte a1 = state[1][col];
        byte a2 = state[2][col];
        byte a3 = state[3][col];
        // MixColumns 행렬 곱셈: [02 03 01 01] * [a0, a1, a2, a3]^T
        state[0][col] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        state[1][col] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        state[2][col] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        state[3][col] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

// 역 MixColumns
static void aes_inv_mixcolumns(byte state[4][4]) {
    for (int col = 0; col < 4; col++) {
        byte a0 = state[0][col];
        byte a1 = state[1][col];
        byte a2 = state[2][col];
        byte a3 = state[3][col];
        // 역 MixColumns 행렬 곱셈: [0e 0b 0d 09] * [a0, a1, a2, a3]^T (gmul 사용)
        state[0][col] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        state[1][col] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        state[2][col] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        state[3][col] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

// AddRoundKey 단계
static void aes_addroundkey(const word* w, byte state[4][4], int round) {
    for (int col = 0; col < 4; col++) {
        // 라운드 키는 w[round*4 + col]에 저장되어 있음
        word k = w[round*4 + col];
        state[0][col] ^= (byte)(k >> 24);
        state[1][col] ^= (byte)(k >> 16);
        state[2][col] ^= (byte)(k >>  8);
        state[3][col] ^= (byte)k;
    }
}

// RotWord: 워드 내 바이트를 왼쪽으로 한 칸 순환
static word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

// SubWord: 워드의 각 바이트에 S-box 적용
static word SubWord(word w) {
    return ((word)sbox[(w >> 24) & 0xFF] << 24) |
           ((word)sbox[(w >> 16) & 0xFF] << 16) |
           ((word)sbox[(w >>  8) & 0xFF] <<  8) |
           ((word)sbox[w & 0xFF]);
}

// 카운터 블록 구성 (nonce 8바이트 + counter 8바이트)
static void construct_counter_block(byte counter_block[AES_BLOCK_SIZE], const byte* nonce, uint64_t counter) {
    // 앞 8바이트 = nonce (128비트 nonce를 가정하고 앞 8바이트만 사용하는 방식일 수 있음)
    // 일반적으로 CTR nonce는 전체 16바이트 중 일부를 nonce로, 나머지를 카운터로 사용합니다.
    // 현재 코드는 nonce 8바이트 + counter 8바이트로 구성합니다.
    memcpy(counter_block, nonce, 8);
    // 뒤 8바이트 = counter (Little Endian 방식으로 저장)
    for (int i = 0; i < 8; i++) {
        counter_block[8 + i] = (byte)((counter >> (8 * i)) & 0xFF);
    }
}

// --- 공개 API 함수 구현 ---

// 키 확장 함수 구현
int aes_keyexpansion(const byte* key, word* w, size_t key_len) {
    int Nk = (int)key_len / 4;            // 키 길이(워드 단위)
    int Nr;                               // 라운드 수
    if (Nk == AES_NK_128) Nr = AES_NR_128; // AES-128
    else if (Nk == AES_NK_192) Nr = AES_NR_192; // AES-192
    else if (Nk == AES_NK_256) Nr = AES_NR_256; // AES-256
    else {
        fprintf(stderr, "Unsupported key length: %zu bytes (Nk=%d). Must be 16, 24, or 32 bytes.\n", key_len, Nk);
        return -1;
    }

    // 1. 처음 Nk개의 워드는 키에서 직접 복사 (Big Endian으로 저장)
    for (int i = 0; i < Nk; i++) {
        w[i] = ((word)key[4*i] << 24) | ((word)key[4*i+1] << 16) |
               ((word)key[4*i+2] << 8) | (word)key[4*i+3];
    }

    // 2. 나머지 라운드 키 생성
    // 4 * (Nr + 1)은 전체 라운드 키 워드 수입니다.
    for (int i = Nk; i < 4*(Nr+1); i++) {
        word temp = w[i-1];
        if (i % Nk == 0) {
            // RotWord -> SubWord -> RCON XOR
            temp = SubWord(RotWord(temp)) ^ RCON[(i/Nk)-1];
        } else if (Nk == AES_NK_256 && (i % Nk == 4)) { // Nk > 6 대신 AES_NK_256 사용
            // AES-256 전용: 4의 배수-1 위치에서 SubWord 추가 적용
            temp = SubWord(temp);
        }
        w[i] = w[i-Nk] ^ temp;
    }
    return Nr;  // 라운드 수 반환
}

// AES 블록 암호화 구현
void aes_encrypt(byte input[AES_BLOCK_SIZE], byte output[AES_BLOCK_SIZE], const word* w, int Nr) {
    byte state[4][4];
    // 바이트 배열 -> 4x4 행렬 (열 우선) 변환
    for (int i = 0; i < AES_BLOCK_SIZE; i++) state[i%4][i/4] = input[i];

    // 0. AddRoundKey
    aes_addroundkey(w, state, 0);

    // 1. Nr-1 라운드 반복
    for (int round = 1; round < Nr; round++) {
        aes_subbytes(state);
        aes_shiftrows(state);
        aes_mixcolumns(state);
        aes_addroundkey(w, state, round);
    }

    // 2. 마지막 라운드 (MixColumns 생략)
    aes_subbytes(state);
    aes_shiftrows(state);
    aes_addroundkey(w, state, Nr);

    // 3. 4x4 행렬 -> 바이트 배열 변환 (열 우선)
    for (int i = 0; i < AES_BLOCK_SIZE; i++) output[i] = state[i%4][i/4];
}

// AES 블록 복호화 구현
void aes_decrypt(byte input[AES_BLOCK_SIZE], byte output[AES_BLOCK_SIZE], const word* w, int Nr) {
    byte state[4][4];
    // 바이트 배열 -> 4x4 행렬 (열 우선) 변환
    for (int i = 0; i < AES_BLOCK_SIZE; i++) state[i%4][i/4] = input[i];

    // 0. 초기 AddRoundKey (마지막 라운드 키 사용)
    aes_addroundkey(w, state, Nr);

    // 1. Nr-1 역 라운드 반복
    for (int round = Nr-1; round >= 1; round--) {
        aes_inv_shiftrows(state);
        aes_inv_subbytes(state);
        aes_addroundkey(w, state, round); // 라운드 키 순서는 암호화와 동일
        aes_inv_mixcolumns(state);
    }

    // 2. 마지막 역 라운드 (InvMixColumns 생략)
    aes_inv_shiftrows(state);
    aes_inv_subbytes(state);
    aes_addroundkey(w, state, 0); // 초기 키(0번째 키) 사용

    // 3. 4x4 행렬 -> 바이트 배열 변환
    for (int i = 0; i < AES_BLOCK_SIZE; i++) output[i] = state[i%4][i/4];
}


// CTR 모드 구현 (암호화와 복호화가 동일)
void AES_CTR(const byte *input, byte *output, size_t length,
             const byte *key, const byte *nonce, size_t key_len) {
    // word round_keys[60]은 roundKey[240] 배열 크기와 일치합니다 (60워드 * 4바이트/워드 = 240바이트)
    word round_keys[4 * (AES_NR_256 + 1)]; // 4 * (14 + 1) = 60
    byte counter_block[AES_BLOCK_SIZE];
    byte keystream[AES_BLOCK_SIZE];
    uint64_t counter = 0; // uint64_t는 stdint.h에 정의되어 있으므로 수정하지 않습니다.
    
    // 키 확장
    int Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return; // 유효하지 않은 키 길이

    size_t block_count = (length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    for (size_t i = 0; i < block_count; i++) {
        size_t offset = i * AES_BLOCK_SIZE;
        size_t block_len = (length - offset >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (length - offset);

        // 1. 카운터 블록 생성 (Nonce + Counter)
        construct_counter_block(counter_block, nonce, counter);
        
        // 2. 카운터 블록 암호화 -> 키스트림 생성
        aes_encrypt(counter_block, keystream, round_keys, Nr);

        // 3. 키스트림과 평문/암호문 XOR
        for (size_t j = 0; j < block_len; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }
        counter++;
    }
}

// ECB 모드 구현 (암호화/복호화 통합)
void AES_ECB(const byte *input, byte *output, size_t length,
             const byte *key, size_t key_len, int encrypt) {
    word round_keys[4 * (AES_NR_256 + 1)]; // 60 워드
    
    // 키 확장
    int Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return; // 유효하지 않은 키 길이
    
    // 16바이트 블록 단위로 암호화/복호화
    size_t block_count = length / AES_BLOCK_SIZE;
    for (size_t i = 0; i < block_count; i++) {
        size_t offset = i * AES_BLOCK_SIZE;
        if (encrypt) {
            aes_encrypt((byte*)(input + offset), output + offset, round_keys, Nr);
        } else {
            aes_decrypt((byte*)(input + offset), output + offset, round_keys, Nr);
        }
    }
    
    // 마지막 블록이 16바이트 미만인 경우 (패딩 없이 그대로 복사)
    size_t remaining = length % AES_BLOCK_SIZE;
    if (remaining > 0) {
        memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
    }
}

// CBC 모드 구현 (암호화/복호화 통합)
void AES_CBC(const byte *input, byte *output, size_t length,
             const byte *key, const byte *iv, size_t key_len, int encrypt) {
    word round_keys[4 * (AES_NR_256 + 1)]; // 60 워드
    byte block[AES_BLOCK_SIZE];
    byte prev_block[AES_BLOCK_SIZE];
    byte current_block[AES_BLOCK_SIZE];
    
    // 키 확장
    int Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return; // 유효하지 않은 키 길이
    
    // IV를 이전 블록으로 초기화
    memcpy(prev_block, iv, AES_BLOCK_SIZE);
    
    size_t block_count = length / AES_BLOCK_SIZE;
    
    if (encrypt) {
        // 암호화: 순방향 체이닝
        for (size_t i = 0; i < block_count; i++) {
            size_t offset = i * AES_BLOCK_SIZE;
            
            // 평문과 이전 암호문 블록을 XOR
            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                block[j] = input[offset + j] ^ prev_block[j];
            }
            
            // AES 암호화
            aes_encrypt(block, output + offset, round_keys, Nr);
            
            // 현재 암호문을 다음 라운드의 이전 블록으로 저장
            memcpy(prev_block, output + offset, AES_BLOCK_SIZE);
        }
    } else {
        // 복호화: 역방향 체이닝
        for (size_t i = 0; i < block_count; i++) {
            size_t offset = i * AES_BLOCK_SIZE;
            
            // 현재 암호문 블록 저장 (복호화 전에 저장 필요)
            memcpy(current_block, input + offset, AES_BLOCK_SIZE);
            
            // AES 복호화
            aes_decrypt((byte*)(input + offset), block, round_keys, Nr);
            
            // 복호화된 블록과 이전 암호문 블록을 XOR
            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                output[offset + j] = block[j] ^ prev_block[j];
            }
            
            // 현재 암호문을 다음 라운드의 이전 블록으로 저장
            memcpy(prev_block, current_block, AES_BLOCK_SIZE);
        }
    }
    
    // 마지막 블록이 16바이트 미만인 경우 (패딩 없이 그대로 복사)
    size_t remaining = length % AES_BLOCK_SIZE;
    if (remaining > 0) {
        memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
    }
}

// --- SHA-256 구현 --- (SHA256_CTX 구조체 필드 타입 수정)

// SHA-256 상수 (첫 64개 소수의 세제곱근의 소수 부분)

/* static const uint32_t sha256_k[64] = {
// ... (값 생략)
};

// SHA-256 비트 연산 매크로
#define SHA_ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define SHA_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x) (SHA_ROTRIGHT(x,2) ^ SHA_ROTRIGHT(x,13) ^ SHA_ROTRIGHT(x,22))
#define SHA_EP1(x) (SHA_ROTRIGHT(x,6) ^ SHA_ROTRIGHT(x,11) ^ SHA_ROTRIGHT(x,25))
#define SHA_SIG0(x) (SHA_ROTRIGHT(x,7) ^ SHA_ROTRIGHT(x,18) ^ ((x) >> 3))
#define SHA_SIG1(x) (SHA_ROTRIGHT(x,17) ^ SHA_ROTRIGHT(x,19) ^ ((x) >> 10))

// SHA-256 변환 함수
static void sha256_transform(SHA256_CTX *ctx, const byte data[])
{
    // uint32_t 대신 word 사용
    word a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // 메시지 스케줄 준비
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((word)data[j] << 24) | ((word)data[j + 1] << 16) | ((word)data[j + 2] << 8) | ((word)data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SHA_SIG1(m[i - 2]) + m[i - 7] + SHA_SIG0(m[i - 15]) + m[i - 16];

    // 작업 변수 초기화
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // 64라운드 압축 함수
    for (i = 0; i < 64; ++i) {
        t1 = h + SHA_EP1(e) + SHA_CH(e, f, g) + sha256_k[i] + m[i];
        t2 = SHA_EP0(a) + SHA_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // 중간 해시 값 업데이트
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// SHA-256 초기화
void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    // 초기 해시 값
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// SHA-256 데이터 업데이트
void sha256_update(SHA256_CTX *ctx, const byte data[], size_t len)
{
    word i; // uint32_t 대신 word 사용

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

// SHA-256 최종 해시 계산
void sha256_final(SHA256_CTX *ctx, byte hash[])
{
    word i; // uint32_t 대신 word 사용

    i = ctx->datalen;
    // ... (나머지 로직은 변경 없음)
}

// 편의 함수: 한 번에 SHA-256 해시 계산
void sha256(const byte data[], size_t len, byte hash[])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
} */

// 안전한 키 생성 함수 구현
int generate_secure_key(byte* key, size_t key_len) {
#ifdef _WIN32
    // Windows: BCryptGenRandom 사용
    #include <windows.h>
    #include <bcrypt.h>
    NTSTATUS status = BCryptGenRandom(NULL, key, (ULONG)key_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGenRandom failed with status: 0x%x\n", (unsigned int)status);
        return -1;
    }
#else
    // Linux, macOS 등 Unix 계열: /dev/urandom 사용
    FILE *fp = fopen("/dev/urandom", "rb");
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