#include "sa_peks.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

static int hash_to_zn(mpz_t hash, const char * w) {
    // Map keyword to Z_N^*
	
    const char * pass = "0123456789ABCDEF";
    unsigned char hw_str[HASH_LEN];
    char mpz_str[2*HASH_LEN + 2];

    sha256(w, strlen(w), hw_str);

    for(int i = 0, j = 0; i < HASH_LEN; i++, j++) {
        mpz_str[j] = pass[ hw_str[i] & 0xf ];
        hw_str[i] >>= 4;
        j++;
        mpz_str[j] = pass[ hw_str[i] & 0xf ];
    }
    mpz_str[2*HASH_LEN] = '\0';
    mpz_set_str(hash, mpz_str, 16);

    return STS_OK;
}

static int hash_to_group(mpz_t A, element_t B, const char * w) {
    // Map Z_N^* to Group G1
	
    char buf[512];
    int len;
    len = gmp_snprintf(buf, 256, "%Zx", A);
    if(len > 256) {
        len = 256;
    }
    strcpy(buf + 256, w);
    element_from_hash(B, buf, len + strlen(w));

    return STS_OK;
}

int fdh_rsa_setup(int N_bits, mpz_t N, mpz_t e, mpz_t d) {
    // KS-derived Setup
	gmp_randstate_t rndst;
    mpz_t p, q, phi_N;

    mpz_init(p);
    mpz_init(q);
    mpz_init(phi_N);

    gmp_randinit_default(rndst);
    gmp_randseed_ui(rndst, (unsigned long int)time(NULL));

    mpz_urandomb(p, rndst, N_bits/2);
    if(mpz_even_p(p)) {
        mpz_add_ui(p, p ,1);
    }
    while(mpz_probab_prime_p(p, REPS) == 0) {
        mpz_nextprime(p, p); // mpz_add_ui(p, p, 2);
    }
    
	mpz_urandomb(q, rndst, N_bits/2);
    if(mpz_even_p(q)) {
        mpz_add_ui(q, q ,1);
    }
    while(mpz_probab_prime_p(q, REPS) == 0) {
        mpz_nextprime(q, q); // mpz_add_ui(q, q, 2);
    }
    mpz_mul(N, p, q); // N = p*q

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi_N, p, q); // phi_N = (p-1)*(q-1)

    mpz_urandomb(e, rndst, N_bits);
    while(mpz_cmp(N, e) > 0) {
        mpz_urandomb(e, rndst, N_bits);
    }

    while(mpz_invert(d, e, phi_N) == 0) {
        mpz_urandomb(e, rndst, N_bits);
        while(mpz_cmp(N, e) > 0) {
            mpz_urandomb(e, rndst, N_bits);
        }
    }
	
    gmp_randclear(rndst);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi_N);
	
    return STS_OK;
}

static int ks_derived(mpz_t ksw, mpz_t N, mpz_t e, mpz_t d, const char * w) {
    //Interaction with keyword server
    mpz_t r, hw;
    gmp_randstate_t rndst;

    mpz_init(r);
    mpz_init(hw);
    gmp_randinit_default(rndst);

    hash_to_zn(ksw, w); // H(w) in Z_N^*
    mpz_urandomm(r, rndst, N);
    mpz_powm(hw, r, e, N);
    mpz_mul(ksw, hw, ksw);
    mpz_mod(hw, ksw, N); // w1 = r^e * H(w) mod N

    mpz_powm(ksw, hw, d, N); // w2 = w1^d mod N

    mpz_invert(hw, r, N); 
    mpz_mul(ksw, hw, ksw);
    mpz_mod(ksw, ksw, N); // w3 = r^-1 * w2 mod N

    mpz_clear(r);
    mpz_clear(hw);
    gmp_randclear(rndst);
	
    return STS_OK;
}

int sa_peks_setup(int ec_param, int N_bits, pairing_t pairing, element_t g, element_t pk, element_t sk, mpz_t N, mpz_t e, mpz_t d) {

    pbc_param_t fp;

	if (ec_param < 1) {
		pbc_die("input error");
	}
	//Init Type-F elliptic curve
	pbc_param_init_f_gen(fp, ec_param);
	pairing_init_pbc_param(pairing, fp);
	
    element_init_G2(g, pairing);
    element_random(g);

    element_init_Zr(sk, pairing);
    element_random(sk);

    element_init_G2(pk, pairing);
    element_pow_zn(pk, g, sk); //pk = g^sk
	
	fdh_rsa_setup(N_bits, N, e, d); //Initialize FDH
	
    pbc_param_clear(fp);
    
    return STS_OK;
}


int sa_peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, mpz_t N, mpz_t e, mpz_t d, const char * w) {
    if(w == NULL) {
        return STS_ERR;
    }

    unsigned char gt_data[GT_LEN];
    element_t r, tmp1, tmp2;
    mpz_t Delt;

    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);
    mpz_init(Delt);


    ks_derived(Delt, N, e, d, w); // Get the KS-derived keyword

    hash_to_group(Delt, tmp1, w);

    element_random(r);
    element_pow_zn(Ca, g, r); // Ca = g^r
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk); // Cb = e(H(w)^r,pk)

    element_to_bytes(gt_data, tmp2);
    sha256(gt_data, GT_LEN, Cb);
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    mpz_clear(Delt);
    return STS_OK;
}


int sa_peks_trapdoor(element_t Tw, element_t sk, mpz_t N, mpz_t e, mpz_t d, const char * w) {
    if(w == NULL) {
        return STS_ERR;
    }
    mpz_t delt;
    
    mpz_init(delt);
    
    ks_derived(delt, N, e, d, w); // Get the KS-derived keyword

    hash_to_group(delt, Tw, w);

    element_pow_zn(Tw, Tw, sk); // Tw = H(w)^sk

    mpz_clear(delt);
    return STS_OK;
}


int sa_peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B) {
    if(B == NULL) {
        return STS_ERR;
    }
    element_t tmp;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_GT(tmp, pairing);

    element_pairing(tmp, Tw, A);
    element_to_bytes(gt_data, tmp);
    sha256(gt_data, GT_LEN, hash_data);
    element_clear(tmp);
    if(memcmp(hash_data, B, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}
