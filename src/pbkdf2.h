#ifndef PBKDF2_H
#define PBKDF2_H


#include "hmac/hmac.h"
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
      const uint8_t *salt, size_t salt_len,
      uint32_t iteration_count,
      uint8_t *output, size_t out_len); // 32 bytes
      


#endif