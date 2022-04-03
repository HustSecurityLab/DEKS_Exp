#include "deks.h"
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

int addr[32];
char dataset[640][64];
pairing_t pairing;
element_t g, pk, sk, Tw;
mpz_t N, pi, e, d;
int T, inc;

static double time_cost(struct timeval A, struct timeval B) {
    double res;
    res = (B.tv_sec - A.tv_sec) * 1000000 + B.tv_usec - A.tv_usec;
    return res / 1000; 
}

void * gentest(void * pos) {
	element_t Ca;
    int ptr;
	unsigned char Cb[HASH_LEN];
	element_init_G2(Ca, pairing);
	
    ptr = (*(int *)pos) * inc;

	for(int k = 0; k < inc; k++) {
		deks_encrypt(Ca, Cb, T, pairing, g, pk, N, dataset[ptr+k]);
		deks_test(pairing, Tw, Ca, Cb);
	}
	
	element_clear(Ca);
}

int main(int argc, char * argv[]) {
	char w[64];
    struct timeval start, end;
    int g2_len, zr_len;
    double cost;
	pthread_t pid[32];
	FILE * fp;
	void * ret;
    char * g2_buf, * zr_buf;
    mpz_t phi_N;
    char * ec_param = "type f\nq 16283262548997601220198008118239886027035269286659395419233331082106632227801\nr 16283262548997601220198008118239886026907663399064043451383740756301306087801\nb 7322757890651446833342173470888950103129198494728585151431956701557392549679\nbeta 9776063510951480907546829895586341975790848099009256891110816835958685274282\nalpha0 1776307819061905444848005605541335123416176649043693774569737527341520482926\nalpha1 4922472003107175314522406564324183657125055707028154503359780540299732014568";
    //Type-f BN256

    pairing_init_set_str(pairing, ec_param);
    g2_len = pairing_length_in_bytes_compressed_G2(pairing);
    zr_len = pairing_length_in_bytes_Zr(pairing);
    g2_buf = (char *)malloc(g2_len);
    zr_buf = (char *)malloc(zr_len);

    element_init_G1(Tw, pairing);
    element_init_G2(g, pairing);
    element_init_G2(pk, pairing);
    element_init_Zr(sk, pairing);
	mpz_init(N);
    mpz_init(pi);
    mpz_init(e);
    mpz_init(d);
    mpz_init(phi_N);

    if ((fp = fopen("params.txt", "rb")) == NULL) {
        printf("Please execute benchmark_params_ciphers first!\n");
        return STS_ERR;
    }
    fread(g2_buf, g2_len, 1, fp);
    element_from_bytes_compressed(g, g2_buf);
    fread(g2_buf, g2_len, 1, fp);
    element_from_bytes_compressed(pk, g2_buf);
    fread(zr_buf, zr_len, 1, fp);
    element_from_bytes(sk, zr_buf);
    mpz_inp_raw(N, fp);
    mpz_inp_raw(e, fp);
    mpz_inp_raw(d, fp);
    mpz_inp_raw(phi_N, fp);
    fclose(fp);

    if ((fp = fopen("keyword.txt", "r"))== NULL) {
        printf("Please provide at least 1000 keywords in a file named \'keyword.txt\'.\n");
        return STS_ERR;
    }
    for(int i = 0; i < 640; i++) {
        if(fscanf(fp, "%s", w) != EOF) {
            strcpy(dataset[i], w);
        }else {
            printf("Error!\n");
            break;
        }
    }
    fclose(fp);

    for(int i = 0; i < 32; i++) {
        addr[i] = i;
    }
    strcpy(w, "Henwood");

    printf("DEKS average time cost of generating and testing a ciphertext:(T=2^#,threads)\n");
    for (int i = 18; i < 24; ++i) {
        T = i;
        catalyst_gen(T, phi_N, pi);
        deks_trapdoor(Tw, sk, pi, N, w);

        for (int j = 1; j < 64; j *= 2) {
            inc = 640/j;
            gettimeofday(&start, NULL);
            for(int k = 0; k < j; k++) {
                if(pthread_create(&pid[k], NULL, gentest, (void *)&addr[k]) !=0) {
                    printf("pthread_create err!\n");
                    return -1;
                }
            }

            for(int k = 0; k < j; k++) {
                if(pthread_join(pid[k], &ret) != 0) {
                    printf("pthread_join err!\n");
                    return -1;
                }
            }
            gettimeofday(&end, NULL);
            cost= time_cost(start, end);
            printf("(%2d,%2d) \t%.6f s\n", T, j, cost/640000);
        }
    }

    element_clear(g);
    element_clear(pk);
    element_clear(sk);
	element_clear(Tw);
    mpz_clear(N);
    mpz_clear(pi);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(phi_N);
    pairing_clear(pairing);
    return 0;
}