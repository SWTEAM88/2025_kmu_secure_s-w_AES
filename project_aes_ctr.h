#ifndef PROJECT_AES_CTR_H //파일이 컴파일러에 한 번만 포함되도록 보장하는 안전장치
#define PROJECT_AES_CTR_H

#include <stdint.h>
#include <stddef.h>

// 타입 정의
typedef uint8_t  byte;  // 부호 없는 8비트 정수형
typedef uint32_t word;  // 부호 없는 32비트 정수형

// AES 블록 크기 (128비트 = 16바이트)
#define AES_BLOCK_SIZE 16

// AES 매개변수
#define AES_NB 4   // 블록당 32비트 워드 수 (항상 4)
#define AES_NK_128 4  // AES-128: 키 길이 4워드 (16바이트)
#define AES_NK_192 6  // AES-192: 키 길이 6워드 (24바이트)
#define AES_NK_256 8  // AES-256: 키 길이 8워드 (32바이트)

#define AES_NR_128 10 // AES-128: 라운드 수
#define AES_NR_192 12 // AES-192: 라운드 수
#define AES_NR_256 14 // AES-256: 라운드 수


// AES 상태 구조체 (CTR, CBC, ECB 공통 사용 가능)
typedef struct {
    byte roundKey[240];   // 확장된 키 저장 공간 (최대 AES-256 기준)
    int Nr;               // 라운드 수
    byte iv[16];          // 초기 벡터 (CBC/CTR용)
    byte nonce[16];       // CTR용 nonce (옵션)
} AES_CTX;

// SHA-256 컨텍스트 구조체
typedef struct {
    byte data[64];         // 입력 데이터 블록
    uint32_t datalen;      // 현재 블록의 길이
    uint64_t bitlen;       // 전체 입력 비트 길이
    uint32_t state[8];     // 해시 상태
} SHA256_CTX;

// AES 관련 함수 선언
int aes_keyexpansion(const byte* key, word* w, size_t key_len);

void aes_encrypt(byte input[16], byte output[16], const word* w, int Nr);
void aes_decrypt(byte input[16], byte output[16], const word* w, int Nr);

// AES 운영 모드 함수 선언
// encrypt: 1=암호화, 0=복호화
void AES_ECB(const byte *input, byte *output, size_t length,
             const byte *key, size_t key_len, int encrypt);

void AES_CBC(const byte *input, byte *output, size_t length,
             const byte *key, const byte *iv, size_t key_len, int encrypt);

void AES_CTR(const byte *input, byte *output, size_t length,
             const byte *key, const byte *nonce, size_t key_len);

// SHA-256 함수 선언
/* void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const byte data[], size_t len);
void sha256_final(SHA256_CTX *ctx, byte hash[]);
void sha256(const byte data[], size_t len, byte hash[]); */

// 유틸리티 함수
int generate_secure_key(byte* key, size_t key_len);

#endif // PROJECT_AES_CTR_H