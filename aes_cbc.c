
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>

// AES 加密函数
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new");
        return -1;
    }

    // 初始化加密操作，使用 AES-128-CBC 模式
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        perror("EVP_EncryptInit_ex");
        return -1;
    }

    // 禁用填充
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // 加密更新，输入明文，输出密文
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        perror("EVP_EncryptUpdate");
        return -1;
    }
    ciphertext_len = len;

    // 完成加密操作
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        perror("EVP_EncryptFinal_ex");
        return -1;
    }
    ciphertext_len += len;

    // 清理上下文
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES 解密函数
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new");
        return -1;
    }

    // 初始化解密操作，使用 AES-128-CBC 模式
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        perror("EVP_DecryptInit_ex");
        return -1;
    }

    // 禁用填充
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // 解密更新，输入密文，输出明文
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        perror("EVP_DecryptUpdate");
        return -1;
    }
    plaintext_len = len;

    // 完成解密操作
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        perror("EVP_DecryptFinal_ex");
        return -1;
    }
    plaintext_len += len;

    // 清理上下文
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main() {
    // 示例密钥和 IV，16 字节 (128 位) 的 AES 密钥和初始化向量
    unsigned char key[16] = {0x15, 0x18, 0x0F, 0x23, 0xC0, 0x51, 0xD0, 0x19, 0x10, 0x82, 0x81, 0x81, 0x0F, 0x24, 0x50, 0x50};
    unsigned char iv[16];

    memset(iv, 0x11, sizeof(iv));

    // 明文
    unsigned char plaintext[16];
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];

    memset(plaintext, 0x11, sizeof(plaintext));

    int ciphertext_len, decryptedtext_len;

    // AES CBC 加密
    ciphertext_len = aes_encrypt(plaintext, 16, key, iv, ciphertext);
    printf("cipher text size: %d, defail is:\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    // AES CBC 解密
    decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    printf("plain text size: %d, defail is:\n", decryptedtext_len);
    for(int i = 0; i < decryptedtext_len; i++)
        printf("%02x", decryptedtext[i]);
    printf("\n");


    return 0;
}


