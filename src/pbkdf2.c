#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

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


int F(const uint8_t *password, size_t password_len,
      const uint8_t *salt, size_t salt_len,
      uint32_t iteration_count,
      uint32_t block_index,
      uint8_t *output){

      }