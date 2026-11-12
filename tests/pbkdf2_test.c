#include "pbkdf2.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int run_case(const char* name, const char* password, const char* salt, uint32_t iterations, size_t out_len, const char* expected_hex){
    uint8_t out[64];
    if(out_len > sizeof(out)){
        printf("%s : FAIL (outlen and out not the same size)\n", name);
        return 1;
    }
    if(pbkdf2_hmac_sha256((const uint8_t*) password, strlen(password), (const uint8_t*) salt, strlen(salt), iterations, out, out_len ) != 0){
        printf("%s: FAIL (PBKDF2 failure) \n", name);
        return 1;
    }
    char hex[129];
    for(size_t i = 0; i < out_len; i++){
        sprintf(hex + 2 * i, "%02x", out[i]);
    }

    if(strcmp(hex, expected_hex) != 0){   
        printf("%s : FAIL\n", name);
        printf("  got:      %s\n  expected: %s\n", hex, expected_hex);
        return 1;
    }else{
        printf("%s : PASS\n", name);
        printf("  got:      %s\n  expected: %s\n", hex, expected_hex);
    }
    return 0;
}
int main(void){
    int failures = 0;
    //came from Python hashlib.pbkdf2_hmac
    const char* expected_hex_one = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b";
    const char* expected_hex_two = "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43";
    const char* expected_hex_three = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a";
    const char* expected_hex_four =  "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9";
    const char* expected_hex_five = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";

    failures += run_case("case 1", "password", "salt", 1 , 32, expected_hex_one);
    failures += run_case("case 2", "password", "salt", 2, 32, expected_hex_two);
    failures += run_case("case 3", "password", "salt", 4096, 32, expected_hex_three);
    failures += run_case("case 4", "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40, expected_hex_four);
    failures += run_case("case 5", "passwrd", "salt", 1, 64, expected_hex_five);

    //Error Paths
    uint8_t out_f1[32];
    if(pbkdf2_hmac_sha256(NULL, 0, (const uint8_t*) "salt",4, 1, out_f1, 32) != 0){
        printf("NULL password test : PASS (Didn't accept null password)\n");

    } else{
        printf("NULL password test: FAIL (accepted NULL password)\n");
        failures++;
    }
    uint8_t out_f2[32];
    if(pbkdf2_hmac_sha256((const uint8_t*) "password", strlen("password"), (const uint8_t*) "salt", 4, 1, out_f2, 0) != 0){
        printf("outlen == 0 test : PASS (didn't accept outlen == 0)\n");
    }else{
        printf("outlen == 0 test: FAIL (accepted outlen == 0)\n");
        failures++;
    }
    uint8_t out_f3[32];
    if(pbkdf2_hmac_sha256((const uint8_t*) "password", strlen("password"), (const uint8_t*) "salt", 4, 0, out_f3, sizeof(out_f3)) != 0){
        printf("iteration_count == 0 test : PASS (didn't accept)\n");
    }else{
        printf("iteration count == 0: FAIL (accepted it)\n");
        failures++;
    }
    uint8_t out_f4[32];
    uint8_t salt_f4[65];
    memset(salt_f4, 0xFF, 65);
    if(pbkdf2_hmac_sha256((const uint8_t*) "password", strlen("password"), salt_f4, 65, 1, out_f4, 32) != 0){
        printf("Big Salt test: PASS\n");
    }else{
        printf("Big Salt test: FAIL\n");
        failures++;
    }
    printf("Total failures: %i \n", failures);
    return failures != 0;
}