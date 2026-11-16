# PBKDF2-HMAC-SHA256 from Scratch (C)

This is a from scratch implementation of the Password-Based-Key-Derivation-Function-2 (using HMAC-SHA256),
using no external cryptographic libraries.

This is part of an ongoing project working toward a password-protected folder locker with encryption.

## Security Disclaimer

This has not been audited by third parties. While the algorithm is correct that
does not guarantee total security. Consider this a warning in case you intend
to use it.

## How it works

DK = PBKDF2(PRF, password, salt, c, dk_len)

DK = Derived Key.
PRF = In our case this is HMAC-SHA256
password = The password from which we will derive a key.
salt = salt.
c = number of iterations.
dk_len = The desired byte-length of DK.

This implementation works in 32-byte blocks (Ti) indexed at 1 (as specified in NIST)
With T_last being truncated to fit the requested size (If the dk_len isn't a multiple of 32).
Where:
DK = T1 + T2 + T3 ...
Ti = F(password, salt, c, i)

With F being the XOR of c iterations of PRFs. The first PRF uses the PRF key, and the subsequent 
use password as the PRF key (with the first PRF output as input). Basically :
F(password, salt, c, i) = U1 XOR U2 XOR U3 ... Uc
With:
U1 = PRF(password, Salt + (32 bit integer))
Uc = PRF(password, U(c-1))

## API and Design-Notes
The signature is :
```c
int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
      const uint8_t *salt, size_t salt_len, uint32_t iteration_count, uint8_t *output, size_t out_len);  
```
It returns 0 on success and -1 on failure/bad inputs (NULL pointers, `iteration_count == 0`, `out_len == 0`, `salt_len > 64`)
The password is borrowed from the caller thus it isn't changed or scrubbed.
All other sensitive pointers are scrubbed (using `secure_zero()` for reasons stated in the HMAC-SHA256 README.md)
Any other PRF could be used if the appropriate changes are made to `pbkdf2.c`.

## How to use
`make run` -> compiles the project and executes `./test_pbkdf2`.
`make` -> compiles.

## Test vectors 
From [RFC7914](https://www.rfc-editor.org/rfc/rfc7914) and Python `hashlib.pbkdf2_hmac`.

## HMAC-SHA256
[HMAC-SHA256](https://github.com/LamprosM-prog/HMAC-SHA256)