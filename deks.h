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
#define REPS 10

static int hash_keyword(mpz_t hash, const char * w);
// Map keyword to Z_N^*

static int hash_rsa_ring(mpz_t A, element_t B);
// Map Z_N^* to Group G1

int catalyst_gen(int T, mpz_t phi_N, mpz_t pi);

int RSF_gen(int N_bits, int T, mpz_t N, mpz_t pi, mpz_t phi_N);

int deks_setup(int ec_param, int N_bits, int T, pairing_t pairing, element_t g, element_t pk, element_t sk, mpz_t N, mpz_t pi, mpz_t phi_N);

int deks_encrypt(element_t Ca, unsigned char * Cb, int T, pairing_t pairing, element_t g, element_t pk, mpz_t N, const char * w);

int deks_encrypt_catalyst(element_t Ca, unsigned char * Cb, int T, pairing_t pairing, element_t g, element_t pk, mpz_t pi, mpz_t N, const char * w);

int deks_trapdoor(element_t Tw, element_t sk, mpz_t pi, mpz_t N, const char * w);

int deks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B);