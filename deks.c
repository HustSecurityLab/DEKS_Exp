#include "deks.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

static int hash_keyword(mpz_t hash, const char * w) {
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

static int hash_rsa_ring(mpz_t A, element_t B) {
    // Map Z_N^* to Group G1
    char buf[256];
    int len;
    len = gmp_snprintf(buf, 256, "%Zx", A);
    if(len > 256) {
        len = 256;
    }
    element_from_hash(B, buf, len);

    return STS_OK;
}

int catalyst_gen(int T, mpz_t phi_N, mpz_t pi) {
	// pi = 2^(2^T) (mod phi_N)
	mpz_set_ui(pi, 2);
	for(int i = 0; i < T; i++) {
		mpz_powm_ui(pi, pi, 2, phi_N);
	}
	
	return STS_OK;
}

int RSF_gen(int N_bits, int T, mpz_t N, mpz_t pi, mpz_t phi_N) {
	gmp_randstate_t rndst;
	mpz_t p, q, tmp;
	
	mpz_init(p);
	mpz_init(q);
	mpz_init(tmp);
	//mpz_init(phi_N);
	
	gmp_randinit_default(rndst);
    gmp_randseed_ui(rndst, (unsigned long int)time(NULL));
	
	int flag = 1;
    mpz_urandomb(p, rndst, N_bits/2 - 2);
    if(mpz_even_p(p)) {
        mpz_add_ui(p, p ,1);
    }
	while(flag) {
	    while(mpz_probab_prime_p(p, REPS) == 0) {
			mpz_nextprime(p, p);
		}
		mpz_nextprime(tmp, p);

		flag = 0;
		mpz_mul_ui(p, p, 2);
		mpz_add_ui(p, p, 1);
		if(mpz_probab_prime_p(p, REPS) == 0) {
			flag = 1;
            mpz_set(p, tmp);
			continue;
		}
		mpz_mul_ui(p, p, 2);
		mpz_add_ui(p, p, 1);
		if(mpz_probab_prime_p(p, REPS) == 0) {
			flag = 1;
            mpz_set(p, tmp);
			continue;
		}
	}
	
	flag = 1;
    mpz_urandomb(q, rndst, N_bits/2 - 2);
    if(mpz_even_p(q)) {
        mpz_add_ui(q, q ,1);
    }
	while(flag) {
		while(mpz_probab_prime_p(q, REPS) == 0) {
			mpz_nextprime(q, q);
		}

        mpz_nextprime(tmp, q);

		flag = 0;
		mpz_mul_ui(q, q, 2);
		mpz_add_ui(q, q, 1);
		if(mpz_probab_prime_p(q, REPS) == 0) {
			flag = 1;
            mpz_set(q, tmp);
			continue;
		}
		mpz_mul_ui(q, q, 2);
		mpz_add_ui(q, q, 1);
		if(mpz_probab_prime_p(q, REPS) == 0) {
			flag = 1;
            mpz_set(q, tmp);
			continue;
		}
	}
	// gmp_printf("%ZX\n%ZX\n", p, q);
    mpz_mul(N, p, q); // N = p*q

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi_N, p, q); // phi_N = (p-1)*(q-1)
	
	catalyst_gen(T, phi_N, pi);
	
	gmp_randclear(rndst);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(tmp);

	return STS_OK;
}

int deks_setup(int ec_param, int N_bits, int T, pairing_t pairing, element_t g, element_t pk, element_t sk, mpz_t N, mpz_t pi, mpz_t phi_N) {
        
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
    element_pow_zn(pk, g, sk); // pk = g^sk
	
	RSF_gen(N_bits, T, N, pi, phi_N);
    
	pbc_param_clear(fp);
    return STS_OK;
}

int deks_encrypt(element_t Ca, unsigned char * Cb, int T, pairing_t pairing, element_t g, element_t pk, mpz_t N, const char * w) {
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

    // Delta = H_1(w) ^ (2^T) (mod N)
    hash_keyword(Delt, w);
    for(unsigned long long int i = 1 << T; i != 0; i--) {
        mpz_powm_ui(Delt, Delt, 2, N);
    }
    
    hash_rsa_ring(Delt, tmp1);
    element_random(r); // random r
    element_pow_zn(Ca, g, r); // Ca = g^r
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk); // Cb = H_3( e(H_2(Delta)^r,pk) )
    element_to_bytes(gt_data, tmp2);
    sha256(gt_data, GT_LEN, Cb);
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    mpz_clear(Delt);
    return STS_OK;
}

int deks_encrypt_catalyst(element_t Ca, unsigned char * Cb, int T, pairing_t pairing, element_t g, element_t pk, mpz_t pi, mpz_t N, const char * w) {
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

    // Delta = H_1(w) ^ (pi) (mod N)
    hash_keyword(Delt, w);
    mpz_powm(Delt, Delt, pi, N); 

    hash_rsa_ring(Delt, tmp1);
    element_random(r); // random r
    element_pow_zn(Ca, g, r); // Ca = g^r
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk); // Cb = H_3( e(H_2(Delta)^r,pk) )
    element_to_bytes(gt_data, tmp2);
    sha256(gt_data, GT_LEN, Cb);
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    mpz_clear(Delt);
    return STS_OK;
}

int deks_trapdoor(element_t Tw, element_t sk, mpz_t pi, mpz_t N, const char * w) {
    if(w == NULL) {
        return STS_ERR;
    }
    mpz_t delt;
    
    mpz_init(delt);
    // Delta = H_1(w) ^ pi (mod N)
    hash_keyword(delt, w);
    mpz_powm(delt, delt, pi, N);    
    hash_rsa_ring(delt, Tw);
    element_pow_zn(Tw, Tw, sk); // Tw = H_2(Delta) ^ sk

    mpz_clear(delt);
    return STS_OK;
}


int deks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B) {
    if(B == NULL) {
        return STS_ERR;
    }
    element_t tmp;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_GT(tmp, pairing);
    element_pairing(tmp, Tw, A); // e(T_w, Ca)
    element_to_bytes(gt_data, tmp);
    sha256(gt_data, GT_LEN, hash_data); // H_3( e(T_w, Ca) )
    element_clear(tmp);
    if(memcmp(hash_data, B, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}
