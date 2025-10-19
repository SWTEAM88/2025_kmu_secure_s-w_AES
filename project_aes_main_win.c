#include <stdio.h>    
#include <stdlib.h>   
#include <string.h>   
#include <ctype.h>    
#include "project_aes_win.h" 
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

// --- 함수 프로토타입 선언 ---
void setup_console();
void print_hex(const byte* data, size_t len);
char* read_dynamic_line(const char* prompt);
byte* hex_string_to_bytes(const char* hex_str, size_t* out_len);
void test_ecb(size_t key_len, int operation);
void test_cbc(size_t key_len, int operation);
void test_ctr(size_t key_len, int operation);
void test_sha256();


byte* hex_string_to_bytes(const char* hex_str, size_t* out_len) {
    size_t len = strlen(hex_str);
    size_t hex_chars = 0;
    for (size_t i = 0; i < len; ++i) {
        if (!isspace(hex_str[i])) hex_chars++;
    }

    if (hex_chars % 2 != 0) {
        fprintf(stderr, "Error: Hex string must have even length.\n");
        return NULL;
    }

    *out_len = hex_chars / 2;
    byte* bytes = (byte*)malloc(*out_len);
    if (bytes == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    size_t byte_idx = 0;
    for (size_t i = 0; i < len && byte_idx < *out_len; ) {
        while (i < len && isspace(hex_str[i])) i++;
        if (i >= len) break;
        sscanf_s(&hex_str[i], "%2hhx", &bytes[byte_idx++]);
        i += 2;
    }
    return bytes;
}

// 출력 함수
void print_hex(const byte* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}


char* read_dynamic_line(const char* prompt) {
    size_t capacity = 128;
    char* buffer = (char*)malloc(capacity);
    if (buffer == NULL) return NULL;

    size_t len = 0;
    int c;

    // 입력 버퍼 정리
    while ((c = getchar()) != '\n' && c != EOF);

    printf("%s", prompt);

    while ((c = fgetc(stdin)) != '\n' && c != EOF) {
        if (len + 1 >= capacity) {
            capacity *= 2;
            char* new_buffer = (char*)realloc(buffer, capacity);
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

// SHA-256 테스트 함수 (기본 구현)
void test_sha256() {
    printf("\n========== SHA-256 Hash Function Test ==========\n\n");
    printf("(SHA-256 Function not yet implemented.)\n");
}

// ECB 모드 테스트 함수
void test_ecb(size_t key_len, int operation) {
    printf("\n========== AES-ECB Mode Test (AES-%zu) ==========\n\n", key_len * 8);
    byte* key = malloc(key_len);
    if (!key) { fprintf(stderr, "Memory allocation failed\n"); return; }
    for (size_t i = 0; i < key_len; i++) key[i] = (byte)(i + 1); // Test key
    printf("Test Key:\n"); print_hex(key, key_len); printf("\n");

    if (operation == 1) { // Encryption
        char* plaintext_input = read_dynamic_line("Enter plaintext: ");
        if (!plaintext_input) { free(key); return; }

        size_t len = strlen(plaintext_input);
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte* padded_pt = calloc(padded_len, 1);
        memcpy(padded_pt, plaintext_input, len);

        byte* ciphertext = malloc(padded_len);

        printf("Plaintext: %s\n", plaintext_input);
        AES_ECB(padded_pt, ciphertext, padded_len, key, key_len, 1);

        printf("Ciphertext (HEX):\n"); print_hex(ciphertext, padded_len);

        free(plaintext_input); free(padded_pt); free(ciphertext);
    }
    else { // Decryption
        char* hex_input = read_dynamic_line("Enter ciphertext (HEX): ");
        if (!hex_input) { free(key); return; }

        size_t cipher_len;
        byte* ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(key); free(hex_input); return; }

        byte* decrypted = malloc(cipher_len + 1);

        AES_ECB(ciphertext, decrypted, cipher_len, key, key_len, 0);
        decrypted[cipher_len] = '\0';

        printf("Decrypted text: %s\n", decrypted);

        free(hex_input); free(ciphertext); free(decrypted);
    }
    free(key);
}

// CBC 모드 테스트 함수 
void test_cbc(size_t key_len, int operation) {
    printf("\n========== AES-CBC Mode Test (AES-%zu) ==========\n\n", key_len * 8);
    byte* key = malloc(key_len);
    byte iv[16];
    if (!key) { fprintf(stderr, "Memory allocation failed\n"); return; }
    for (size_t i = 0; i < key_len; i++) key[i] = (byte)(i + 1); // Test key
    for (size_t i = 0; i < 16; i++) iv[i] = (byte)(i + 0x10);    // Test IV
    printf("Test Key:\n"); print_hex(key, key_len);
    printf("Test IV:\n"); print_hex(iv, 16); printf("\n");

    if (operation == 1) { // Encryption
        char* plaintext_input = read_dynamic_line("Enter plaintext: ");
        if (!plaintext_input) { free(key); return; }

        size_t len = strlen(plaintext_input);
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte* padded_pt = calloc(padded_len, 1);
        memcpy(padded_pt, plaintext_input, len);
        byte* ciphertext = malloc(padded_len);

        printf("Plaintext: %s\n", plaintext_input);
        AES_CBC(padded_pt, ciphertext, padded_len, key, iv, key_len, 1); // Encryption function call

        printf("Ciphertext (HEX):\n"); print_hex(ciphertext, padded_len);

        free(plaintext_input); free(padded_pt); free(ciphertext);
    }
    else { // Decryption
        char* hex_input = read_dynamic_line("Enter ciphertext (HEX): ");
        if (!hex_input) { free(key); return; }

        size_t cipher_len;
        byte* ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(key); free(hex_input); return; }

        byte* decrypted = malloc(cipher_len + 1);

        AES_CBC(ciphertext, decrypted, cipher_len, key, iv, key_len, 0); // Decryption function call
        decrypted[cipher_len] = '\0'; // Add null terminator

        printf("Decrypted text: %s\n", decrypted);

        free(hex_input); free(ciphertext); free(decrypted);
    }
    free(key);
}

// CTR 모드 테스트 함수 
void test_ctr(size_t key_len, int operation) {
    printf("\n========== AES-CTR Mode Test (AES-%zu) ==========\n\n", key_len * 8);
    byte* key = malloc(key_len);
    byte nonce[8];
    if (!key) { fprintf(stderr, "Memory allocation failed\n"); return; }
    for (size_t i = 0; i < key_len; i++) key[i] = (byte)(i + 1); // Test key
    for (size_t i = 0; i < 8; i++) nonce[i] = (byte)(i + 0x20); // Test Nonce
    printf("Test Key:\n"); print_hex(key, key_len);
    printf("Test Nonce:\n"); print_hex(nonce, 8); printf("\n");

    if (operation == 1) { // Encryption
        char* plaintext_input = read_dynamic_line("Enter plaintext: ");
        if (!plaintext_input) { free(key); return; }

        size_t len = strlen(plaintext_input);
        byte* ciphertext = malloc(len);

        printf("Plaintext: %s\n", plaintext_input);
        AES_CTR((byte*)plaintext_input, ciphertext, len, key, nonce, key_len); // Encryption function call

        printf("Ciphertext (HEX):\n"); print_hex(ciphertext, len);

        free(plaintext_input); free(ciphertext);
    }
    else { // Decryption
        char* hex_input = read_dynamic_line("Enter ciphertext (HEX): ");
        if (!hex_input) { free(key); return; }

        size_t cipher_len;
        byte* ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(key); free(hex_input); return; }

        byte* decrypted = malloc(cipher_len + 1);

        AES_CTR(ciphertext, decrypted, cipher_len, key, nonce, key_len); // Decryption function call
        decrypted[cipher_len] = '\0';

        printf("Decrypted text: %s\n", decrypted);

        free(hex_input); free(ciphertext); free(decrypted);
    }
    free(key);
}

// --- MAIN 함수 ---
int main() {
    int op_choice = 0, mode_selection = 0, key_selection = 0;
    size_t key_len = 0;

    printf("=======================================================\n");
    printf("  AES Encryption/Decryption Test Program\n");
    printf("=======================================================\n\n");

    // 1. Operation selection (Encryption / Decryption)
    while (1) {
        printf("Please select an operation:\n");
        printf("1. Encryption\n");
        printf("2. Decryption\n");
        printf("\nChoice (1-2): ");
        if (scanf_s("%d", &op_choice) == 1 && (op_choice == 1 || op_choice == 2)) {
            break;
        }
        fprintf(stderr, "Invalid input. Please enter 1 or 2.\n\n");
        while (getchar() != '\n'); // Clear input buffer
    }

    // 2. Mode selection
    while (1) {
        printf("\nPlease select a test mode:\n");
        printf("1. SHA-256 \n");
        printf("2. AES-ECB Mode\n");
        printf("3. AES-CBC Mode\n");
        printf("4. AES-CTR Mode\n");
        printf("5. Test All AES Modes\n");
        printf("\nChoice (1-5): ");
        if (scanf_s("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 5) {
            break;
        }
        fprintf(stderr, "Invalid input. Please enter a number between 1-5.\n\n");
        while (getchar() != '\n');
    }

    // 3. Key length selection (for AES modes)
    if (mode_selection >= 2 && mode_selection <= 5) {
        while (1) {
            printf("\nPlease select AES key length (128, 192, 256): ");
            if (scanf_s("%d", &key_selection) == 1) {
                if (key_selection == 128) { key_len = 16; break; }
                if (key_selection == 192) { key_len = 24; break; }
                if (key_selection == 256) { key_len = 32; break; }
            }
            else {
                while (getchar() != '\n'); // Remove invalid input
            }
            fprintf(stderr, "Invalid key length. Please enter 128, 192, or 256.\n");
        }
    }

    // 4. Execute selected mode
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
        printf("\n--- Testing All AES Modes (AES-%zu) ---\n", key_len * 8);
        test_ecb(key_len, op_choice);
        test_cbc(key_len, op_choice);
        test_ctr(key_len, op_choice);
        break;
    }

    printf("\n=======================================================\n");
    printf("  Test Completed!\n");
    printf("=======================================================\n");

    return 0;
}
