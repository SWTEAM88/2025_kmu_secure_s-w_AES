#ifndef PROJECT_AES_CTR_H 
#define PROJECT_AES_CTR_H

#include <stdint.h>
#include <stddef.h>

// 타입 정의
typedef uint8_t  byte;
typedef uint32_t word;

// AES 블록 크기 
#define AES_BLOCK_SIZE 16

// AES 매개변수
#define AES_NB 4 
#define AES_NK_128 4
#define AES_NK_192 6
#define AES_NK_256 8 

#define AES_NR_128 10
#define AES_NR_192 12
#define AES_NR_256 14 

// SHA-256 해시컨텍스트 구조체
typedef struct {
    byte data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

// AES 내부 함수 선언
int aes_keyexpansion(const byte* key, word* w, size_t key_len);

void aes_encrypt(byte input[16], byte output[16], const word* w, int Nr);
void aes_decrypt(byte input[16], byte output[16], const word* w, int Nr);

// AES
// encrypt: 1=암호화, 0=복호화
void AES_ECB(const byte* input, byte* output, size_t length,
    const byte* key, size_t key_len, int encrypt);

void AES_CBC(const byte* input, byte* output, size_t length,
    const byte* key, const byte* iv, size_t key_len, int encrypt);

void AES_CTR(const byte* input, byte* output, size_t length,
    const byte* key, const byte* nonce, size_t key_len);

// SHA-256 함수 선언
void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, const byte data[], size_t len);
void sha256_final(SHA256_CTX* ctx, byte hash[]);
void sha256(const byte data[], size_t len, byte hash[]);

// 보안키 생성 함수
int generate_secure_key(byte* key, size_t key_len);

#endif // PROJECT_AES_CTR_H