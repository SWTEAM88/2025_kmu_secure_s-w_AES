#ifndef PROJECT_AES_WIN_H 
#define PROJECT_AES_WIN_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t  byte;
typedef uint32_t word;

#define AES_BLOCK_SIZE 16

#define AES_NB 4 
#define AES_NK_128 4
#define AES_NK_192 6
#define AES_NK_256 8 

#define AES_NR_128 10
#define AES_NR_192 12
#define AES_NR_256 14 


// AES
int aes_keyexpansion(const byte* key, word* w, size_t key_len);

void aes_encrypt(byte input[16], byte output[16], const word* w, int Nr);
void aes_decrypt(byte input[16], byte output[16], const word* w, int Nr);

// AES mode
// encrypt: 1=enc, 0=dec
void AES_ECB(const byte* input, byte* output, size_t length,
    const byte* key, size_t key_len, int encrypt);

void AES_CBC(const byte* input, byte* output, size_t length,
    const byte* key, const byte* iv, size_t key_len, int encrypt);

void AES_CTR(const byte* input, byte* output, size_t length,
    const byte* key, const byte* nonce, size_t key_len);

//// SHA-256
//void sha256_init(SHA256_CTX* ctx);
//void sha256_update(SHA256_CTX* ctx, const byte data[], size_t len);
//void sha256_final(SHA256_CTX* ctx, byte hash[]);
//void sha256(const byte data[], size_t len, byte hash[]);

int generate_secure_key(byte* key, size_t key_len);

#endif // PROJECT_AES_WIN_H
