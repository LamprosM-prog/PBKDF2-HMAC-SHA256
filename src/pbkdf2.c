#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "pbkdf2.h"

#define MAX_SALT_COUNT 64

static void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}

static void write_u32_be(uint8_t out[4], uint32_t value){
    out[0] = (value >> 24) & 0xFF;
    out[1] = (value >> 16) & 0xFF;
    out[2] = (value >> 8) & 0xFF;
    out[3] = value & 0xFF;
}


static int pbkdf2_f(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t iteration_count, uint32_t block_index, uint8_t *output)
{
    if(password == NULL || salt == NULL || output == NULL || iteration_count == 0 || salt_len > MAX_SALT_COUNT)
    {
        return -1;
    }
    uint8_t salt_block[MAX_SALT_COUNT + 4];
    memcpy(salt_block, salt, salt_len);

    write_u32_be(salt_block + salt_len, block_index);

    uint8_t u[32];
    if(hmac_sha256(password, password_len, salt_block, salt_len + 4, u) != 0){
        secure_zero(u, 32);
        secure_zero(salt_block, salt_len + 4);
        return -1;
    }
    memcpy(output, u, 32);

    for(uint32_t i = 1; i < iteration_count; i++){
        if(hmac_sha256(password, password_len, u, 32, u) != 0){
            secure_zero(u, 32);
            secure_zero(salt_block, salt_len + 4);
            secure_zero(output, 32);
            return -1;
        }

        for(int j = 0; j < 32; j++){
            output[j] ^= u[j];
        }
    }

    secure_zero(u, 32);
    secure_zero(salt_block, salt_len + 4);
    return 0;


}
int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t iteration_count,uint8_t *output, size_t out_len)
{
    if(password == NULL || salt == NULL || output == NULL || out_len == 0){
        return -1;
    }
    uint32_t block_index = 1;
    size_t offset = 0;
    uint8_t temp[32];   
    while(offset < out_len){
        if(pbkdf2_f(password,password_len, salt, salt_len, iteration_count, block_index, temp) != 0){
            secure_zero(temp, 32);
            secure_zero(output, offset);
            return -1;
        }
        size_t remaining = out_len - offset;
        size_t chunk = remaining < 32 ? remaining : 32;
        memcpy(output + offset, temp, chunk);
        offset += chunk;
        block_index++;
    }
    secure_zero(temp,32);
    return 0;
}