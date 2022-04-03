#include "peks.h"

static void sha256(const char * string, int len, unsigned char * buf) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(buf, &sha256);
}

int peks_setup(int ec_param, pairing_t pairing, element_t g, element_t pk, element_t sk) {
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
	
    pbc_param_clear(fp);
	
    return STS_OK;
}


int peks_encrypt(element_t Ca, unsigned char * Cb, pairing_t pairing, element_t g, element_t pk, const char * w) {
    if(w == NULL) {
        return STS_ERR;
    }

    unsigned char gt_data[GT_LEN];
    element_t r, tmp1, tmp2;
    
    element_init_Zr(r, pairing);
    element_init_G1(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    element_from_hash(tmp1, (void*)w, strlen(w));
    
    element_random(r);
    element_pow_zn(Ca, g, r); //Ca = g^r
    element_pow_zn(tmp1, tmp1, r);
    element_pairing(tmp2, tmp1, pk); // e(H_1(w)^r,pk)
	
    element_to_bytes(gt_data, tmp2);
    sha256(gt_data, GT_LEN, Cb); //Cb = H_2( e(H_1(w)^r,pk) )
    
    element_clear(r);
    element_clear(tmp1);
    element_clear(tmp2);
    
    return STS_OK;
}


int peks_trapdoor(element_t Tw, element_t sk, const char * w) {
    if(w == NULL) {
        return STS_ERR;
    }

    element_from_hash(Tw, (void*)w, strlen(w));
    element_pow_zn(Tw, Tw, sk); //Tw = H_1(w)^sk

    return STS_OK;
}


int peks_test(pairing_t pairing, element_t Tw, element_t A, const unsigned char * B) {
    if(B == NULL) {
        return STS_ERR;
    }
    element_t tmp;
    unsigned char gt_data[GT_LEN];
    unsigned char hash_data[HASH_LEN];

    element_init_GT(tmp, pairing);
    element_pairing(tmp, Tw, A); // e(T_w,Ca)
    element_to_bytes(gt_data, tmp);
    sha256(gt_data, GT_LEN, hash_data); // H_2( e(T_w,Ca) )
    
    element_clear(tmp);
    
    if(memcmp(hash_data, B, HASH_LEN) == 0) {
        return STS_EQU;
    } else {
        return STS_OK;
    }
}
