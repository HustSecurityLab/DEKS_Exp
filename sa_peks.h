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
#define REPS 10 // Miller-Rabin testing round

static int hash_keyword(mpz_t hash, const char * w);

static int ks_derived(mpz_t ksw, mpz_t N, mpz_t e, mpz_t d, const char * w);

int fdh_rsa_setup(int N_bits, mpz_t N, mpz_t e, mpz_t d);

int sa_peks_setup(int ec_param, int N_bits, pairing_t pairing, element_t g, element_t pk, element_t sk, mpz_t N, mpz_t e, mpz_t d);

int sa_peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, mpz_t N, mpz_t e, mpz_t d, const char * w);

int sa_peks_trapdoor(element_t Tw, element_t sk, mpz_t N, mpz_t e, mpz_t d, const char * w);

int sa_peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B);