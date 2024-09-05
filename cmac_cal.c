#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void calculate_cmac(const unsigned char *key, const unsigned char *data, size_t data_len) {

    CMAC_CTX *cmac_ctx = CMAC_CTX_new(); // 创建一个 CMAC 上下文
    const EVP_CIPHER *cipher = EVP_aes_128_ecb); // 使用 AES-128 作为块密码算法
    unsigned char cmac_value[EVP_MAX_BLOCK_LENGTH]; // 存储 CMAC 计算结果
    size_t cmac_len = 0;

    // 初始化 CMAC 上下文
    if (!CMAC_Init(cmac_ctx, key, 16, cipher, NULL)) {
        fprintf(stderr, "CMAC_Init failed\n");
        return;
    }

    // 传入数据
    if (!CMAC_Update(cmac_ctx, data, data_len)) {
        fprintf(stderr, "CMAC_Update failed\n");
        return;
    }

    // 获取计算结果
    if (!CMAC_Final(cmac_ctx, cmac_value, &cmac_len)) {
        fprintf(stderr, "CMAC_Final failed\n");
        return;
    }

    // 打印 CMAC 值
    printf("CMAC: ");
    for (size_t i = 0; i < cmac_len; i++) {
        printf("%02x", cmac_value[i]);
    }
    printf("\n");


    printf("plain:: ");
    for(size_t i = 0; i < data_len; i++){
        printf("%02x", data[i]);
    }
    printf("\n");

    // 释放 CMAC 上下文
    CMAC_CTX_free(cmac_ctx);
}

int main() {

    // 示例密钥和数据
    unsigned char key[16];
    unsigned char data[16];


    memset(key, 0xCC, sizeof(key));
    memset(data, 0xAB, sizeof(data));

    // 计算并打印 CMAC
    calculate_cmac(key, data, 16);

    return 0;
}

