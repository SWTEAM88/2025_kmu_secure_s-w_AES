#include <stdio.h>    // printf, fprintf, scanf, fgetc
#include <stdlib.h>   // malloc, free, size_t, calloc, realloc, EXIT_FAILURE
#include <string.h>   // strlen, memcpy
#include <ctype.h>    // isspace
#include "project_aes_ctr.h" 

// byte 타입은 "project_aes_ctr.h"에 이미 정의되어 있습니다 (typedef uint8_t byte;)
// 따라서 아래의 정의는 제거합니다.
// typedef unsigned char byte;


// --- 함수 프로토타입 선언 ---
void print_hex(const byte *data, size_t len);
char* read_dynamic_line(const char *prompt);
byte* hex_string_to_bytes(const char *hex_str, size_t *out_len);
void test_ecb(size_t key_len, int operation);
void test_cbc(size_t key_len, int operation);
void test_ctr(size_t key_len, int operation);
void test_sha256();

/**
 * @brief 16진수 문자열을 바이트 배열로 변환하는 함수
 */
byte* hex_string_to_bytes(const char *hex_str, size_t *out_len) {
    size_t len = strlen(hex_str);
    size_t hex_chars = 0;
    for (size_t i = 0; i < len; ++i) {
        if (!isspace(hex_str[i])) hex_chars++;
    }

    if (hex_chars % 2 != 0) {
        fprintf(stderr, "오류: 16진수 문자열은 짝수 길이어야 합니다.\n");
        return NULL;
    }

    *out_len = hex_chars / 2;
    byte *bytes = (byte *)malloc(*out_len);
    if (bytes == NULL) {
        fprintf(stderr, "메모리 할당 실패\n");
        return NULL;
    }

    size_t byte_idx = 0;
    for (size_t i = 0; i < len && byte_idx < *out_len; ) {
        while (i < len && isspace(hex_str[i])) i++;
        if (i >= len) break;
        // sscanf의 %2hhx는 uint8_t (byte) 2자리를 16진수로 읽는 표준 방식입니다.
        if (sscanf(&hex_str[i], "%2hhx", &bytes[byte_idx++]) != 1) {
            fprintf(stderr, "오류: 16진수 변환에 실패했습니다.\n");
            free(bytes);
            return NULL;
        }
        i += 2;
    }
    return bytes;
}

// 헥스 출력 함수
void print_hex(const byte *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % AES_BLOCK_SIZE == 0) printf("\n"); // AES_BLOCK_SIZE(16) 단위로 줄 바꿈
    }
    if (len % AES_BLOCK_SIZE != 0) printf("\n");
}

/**
 * @brief 사용자로부터 동적으로 한 줄을 입력받는 함수 (수정됨)
 */
char* read_dynamic_line(const char *prompt) {
    size_t capacity = 128;
    char *buffer = (char *)malloc(capacity);
    if (buffer == NULL) return NULL;

    size_t len = 0;
    int c;

    // 이전 입력 버퍼 비우기
    while ((c = fgetc(stdin)) != '\n' && c != EOF);

    printf("%s", prompt);

    while ((c = fgetc(stdin)) != '\n' && c != EOF) {
        if (len + 1 >= capacity) {
            capacity *= 2;
            char *new_buffer = (char *)realloc(buffer, capacity);
            if (new_buffer == NULL) {
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
        buffer[len++] = (char)c;
    }
    buffer[len] = '\0';
    return buffer;
}

// SHA-256 테스트 함수 (원본 유지)
void test_sha256() {
    printf("\n========== SHA-256 해시 함수 테스트 ==========\n\n");
    printf("(SHA-256 함수는 아직 미구현/주석 처리 상태입니다.)\n");
}


// ECB 모드 테스트 함수 (암/복호화 로직 추가)
void test_ecb(size_t key_len, int operation) {
    printf("\n========== AES-ECB 모드 테스트 (AES-%zu) ==========\n\n", key_len * 8);
    byte *key = malloc(key_len);
    if (!key) { fprintf(stderr, "메모리 할당 실패\n"); return; }
    for(size_t i=0; i < key_len; i++) key[i] = (byte)(i + 1); // 임시 키
    printf("사용된 키:\n"); print_hex(key, key_len); printf("\n");

    if (operation == 1) { // 암호화
        char *plaintext_input = read_dynamic_line("평문을 입력하세요: ");
        if (!plaintext_input) { free(key); return; }
        
        size_t len = strlen(plaintext_input);
        // AES_BLOCK_SIZE(16)을 사용하도록 수정
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte *padded_pt = (byte*)calloc(padded_len, 1);
        if (!padded_pt) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(plaintext_input); return; }
        
        memcpy(padded_pt, plaintext_input, len);
        
        byte *ciphertext = (byte*)malloc(padded_len);
        if (!ciphertext) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(plaintext_input); free(padded_pt); return; }
        
        printf("원본 평문: %s\n", plaintext_input);
        AES_ECB(padded_pt, ciphertext, padded_len, key, key_len, 1); // 실제 함수 호출
        
        printf("암호문 (HEX):\n"); print_hex(ciphertext, padded_len);

        free(plaintext_input); free(padded_pt); free(ciphertext);
    } else { // 복호화
        char *hex_input = read_dynamic_line("암호문(HEX)을 입력하세요: ");
        if (!hex_input) { free(key); return; }

        size_t cipher_len;
        byte *ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(key); free(hex_input); return; }
        
        byte *decrypted = (byte*)malloc(cipher_len + 1);
        if (!decrypted) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(hex_input); free(ciphertext); return; }
        
        AES_ECB(ciphertext, decrypted, cipher_len, key, key_len, 0); // 실제 함수 호출
        decrypted[cipher_len] = '\0'; // 패딩 제거 로직 필요

        printf("복호화된 평문: %s\n", decrypted);

        free(hex_input); free(ciphertext); free(decrypted);
    }
    free(key);
}

// CBC 모드 테스트 함수 (암/복호화 로직 추가)
void test_cbc(size_t key_len, int operation) {
    printf("\n========== AES-CBC 모드 테스트 (AES-%zu) ==========\n\n", key_len * 8);
    byte *key = (byte*)malloc(key_len);
    byte iv[AES_BLOCK_SIZE]; // AES_BLOCK_SIZE(16) 사용
    if (!key) { fprintf(stderr, "메모리 할당 실패\n"); return; }
    for(size_t i=0; i < key_len; i++) key[i] = (byte)(i + 1); // 임시 키
    for(size_t i=0; i < AES_BLOCK_SIZE; i++) iv[i] = (byte)(i + 0x10);    // 임시 IV
    printf("사용된 키:\n"); print_hex(key, key_len);
    printf("사용된 IV:\n"); print_hex(iv, AES_BLOCK_SIZE); printf("\n");

    if (operation == 1) { // 암호화
        char *plaintext_input = read_dynamic_line("평문을 입력하세요: ");
        if (!plaintext_input) { free(key); return; }
        
        size_t len = strlen(plaintext_input);
        // AES_BLOCK_SIZE(16)을 사용하도록 수정
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte *padded_pt = (byte*)calloc(padded_len, 1);
        if (!padded_pt) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(plaintext_input); return; }
        
        memcpy(padded_pt, plaintext_input, len);
        byte *ciphertext = (byte*)malloc(padded_len);
        if (!ciphertext) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(plaintext_input); free(padded_pt); return; }
        
        printf("원본 평문: %s\n", plaintext_input);
        AES_CBC(padded_pt, ciphertext, padded_len, key, iv, key_len, 1); // 실제 함수 호출
        
        printf("암호문 (HEX):\n"); print_hex(ciphertext, padded_len);

        free(plaintext_input); free(padded_pt); free(ciphertext);
    } else { // 복호화
        char *hex_input = read_dynamic_line("암호문(HEX)을 입력하세요: ");
        if (!hex_input) { free(key); return; }

        size_t cipher_len;
        byte *ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(key); free(hex_input); return; }
        
        byte *decrypted = (byte*)malloc(cipher_len + 1);
        if (!decrypted) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(hex_input); free(ciphertext); return; }
        
        AES_CBC(ciphertext, decrypted, cipher_len, key, iv, key_len, 0); // 실제 함수 호출
        decrypted[cipher_len] = '\0'; // 패딩 제거 로직 필요

        printf("복호화된 평문: %s\n", decrypted);

        free(hex_input); free(ciphertext); free(decrypted);
    }
    free(key);
}

// CTR 모드 테스트 함수 (암/복호화 로직 추가)
void test_ctr(size_t key_len, int operation) {
    printf("\n========== AES-CTR 모드 테스트 (AES-%zu) ==========\n\n", key_len * 8);
    byte *key = (byte*)malloc(key_len);
    byte nonce[AES_BLOCK_SIZE]; // Nonce 크기를 16바이트로 수정 (8바이트 Nonce + 8바이트 카운터)
    if (!key) { fprintf(stderr, "메모리 할당 실패\n"); return; }
    for(size_t i=0; i < key_len; i++) key[i] = (byte)(i + 1); // 임시 키
    for(size_t i=0; i < AES_BLOCK_SIZE; i++) nonce[i] = (byte)(i + 0x20); // 임시 Nonce/IV
    printf("사용된 키:\n"); print_hex(key, key_len);
    printf("사용된 Nonce/IV:\n"); print_hex(nonce, AES_BLOCK_SIZE); printf("\n");

    if (operation == 1) { // 암호화
        char *plaintext_input = read_dynamic_line("평문을 입력하세요: ");
        if (!plaintext_input) { free(key); return; }

        size_t len = strlen(plaintext_input);
        byte *ciphertext = (byte*)malloc(len);
        if (!ciphertext) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(plaintext_input); return; }
        
        printf("원본 평문: %s\n", plaintext_input);
        // CTR 모드는 암호화/복호화 함수가 동일하며, 패딩이 필요 없습니다.
        AES_CTR((byte*)plaintext_input, ciphertext, len, key, nonce, key_len); // 실제 함수 호출

        printf("암호문 (HEX):\n"); print_hex(ciphertext, len);
        
        free(plaintext_input); free(ciphertext);
    } else { // 복호화
        char *hex_input = read_dynamic_line("암호문(HEX)을 입력하세요: ");
        if (!hex_input) { free(key); return; }

        size_t cipher_len;
        byte *ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(key); free(hex_input); return; }
        
        byte *decrypted = (byte*)malloc(cipher_len + 1);
        if (!decrypted) { fprintf(stderr, "메모리 할당 실패\n"); free(key); free(hex_input); free(ciphertext); return; }

        AES_CTR(ciphertext, decrypted, cipher_len, key, nonce, key_len); // 실제 함수 호출
        decrypted[cipher_len] = '\0';

        printf("복호화된 평문: %s\n", decrypted);
        
        free(hex_input); free(ciphertext); free(decrypted);
    }
    free(key);
}

// --- MAIN 함수 ---
int main() {
    int op_choice = 0, mode_selection = 0, key_selection = 0;
    size_t key_len = 0;
    
    printf("=======================================================\n");
    printf("  AES 암/복호화 테스트 프로그램\n");
    printf("=======================================================\n\n");
    
    // 1. 작업 선택 (암호화 / 복호화)
    while (1) {
        printf("수행할 작업을 선택하세요:\n");
        printf("1. 암호화 (Encrypt)\n");
        printf("2. 복호화 (Decrypt)\n");
        printf("\n선택 (1-2): ");
        if (scanf("%d", &op_choice) == 1 && (op_choice == 1 || op_choice == 2)) {
            break;
        }
        fprintf(stderr, "잘못된 입력입니다. 1 또는 2를 입력하세요.\n\n");
        while (getchar() != '\n'); // 입력 버퍼 비우기
    }
    
    // 2. 모드 선택
    while(1) {
        printf("\n테스트할 모드를 선택하세요:\n");
        printf("1. SHA-256 \n");
        printf("2. AES-ECB 모드\n");
        printf("3. AES-CBC 모드\n");
        printf("4. AES-CTR 모드\n");
        printf("5. 모든 AES 모드 실행\n");
        printf("\n선택 (1-5): ");
        if (scanf("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 5) {
            break;
        }
        fprintf(stderr, "잘못된 입력입니다. 1-5 사이의 숫자를 입력하세요.\n\n");
        while (getchar() != '\n');
    }

    // 3. 키 길이 선택 (AES 모드인 경우)
    if (mode_selection >= 2 && mode_selection <= 5) {
        while (1) {
            printf("\nAES 키 길이를 선택하세요 (128, 192, 256): ");
            if (scanf("%d", &key_selection) == 1) {
                // 헤더 파일의 상수 매크로를 직접 사용하지 않고, 
                // 키 길이를 바이트 수로 설정하는 기존 로직을 유지하면서 헤더 정의와 일치시킵니다.
                if (key_selection == 128) { key_len = AES_NK_128 * 4; break; } // 16
                if (key_selection == 192) { key_len = AES_NK_192 * 4; break; } // 24
                if (key_selection == 256) { key_len = AES_NK_256 * 4; break; } // 32
            } else {
                 while (getchar() != '\n'); // 숫자 아닌 입력값 버리기
            }
            fprintf(stderr, "잘못된 키 길이입니다. 128, 192, 256 중에 다시 입력하세요.\n");
        }
    }
    
    // 4. 선택된 기능 실행
    switch (mode_selection) {
        case 1:
            test_sha256();
            break;
        case 2:
            test_ecb(key_len, op_choice);
            break;
        case 3:
            test_cbc(key_len, op_choice);
            break;
        case 4:
            test_ctr(key_len, op_choice);
            break;
        case 5:
            printf("\n--- 모든 AES 모드 테스트 실행 (AES-%zu) ---\n", key_len * 8);
            test_ecb(key_len, op_choice);
            test_cbc(key_len, op_choice);
            test_ctr(key_len, op_choice);
            break;
    }
    
    printf("\n=======================================================\n");
    printf("  테스트를 성공적으로 마쳤습니다!\n");
    printf("=======================================================\n");
    
    return 0;
}