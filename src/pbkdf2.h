#ifndef PBKDF2_H
#define PBKDF2_H


#include "hmac/hmac.h"
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

int F(const uint8_t *password, size_t password_len,
      const uint8_t *salt, size_t salt_len,
      uint32_t iteration_count,
      uint32_t block_index,
      uint8_t *output); // 32 bytes
      


#endif