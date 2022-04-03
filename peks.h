#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>

#define STS_OK 0
#define STS_EQU 1
#define STS_ERR 2
#define GT_LEN 384
#define HASH_LEN 32

int peks_setup(int ec_param, pairing_t pairing, element_t g, element_t pk, element_t sk);

int peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, const char * w);

int peks_trapdoor(element_t Tw, element_t sk, const char * w);

int peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B);