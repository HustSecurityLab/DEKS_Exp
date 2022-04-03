#include "deks.h"
#include "peks.h"
#include "sa_peks.h"
#include <sys/time.h>

#define TEST_COST 25.55 // Time of testing a ciphertext

char dataset[1024][64];

static double time_cost(struct timeval A, struct timeval B) {
    double res;
    res = (B.tv_sec - A.tv_sec) * 1000000 + B.tv_usec - A.tv_usec;
    return res / 1000; 
}

int main(int argc, char * argv[]) {
    
	char * ec_param = "type f\nq 16283262548997601220198008118239886027035269286659395419233331082106632227801\nr 16283262548997601220198008118239886026907663399064043451383740756301306087801\nb 7322757890651446833342173470888950103129198494728585151431956701557392549679\nbeta 9776063510951480907546829895586341975790848099009256891110816835958685274282\nalpha0 1776307819061905444848005605541335123416176649043693774569737527341520482926\nalpha1 4922472003107175314522406564324183657125055707028154503359780540299732014568";
    //Type-f BN256
    pairing_t pairing;
    element_t g, pk, sk, Ca;
    mpz_t N, pi, e, d, phi_N;
    int g2_len, zr_len;
    FILE * fp;
    char * g2_buf, * zr_buf;
    char w[64], Cb[HASH_LEN];
    struct timeval start, end;
    double cost1, cost2, cost3, kga_cost, result;
    
    pairing_init_set_str(pairing, ec_param);
    g2_len = pairing_length_in_bytes_compressed_G2(pairing);
    zr_len = pairing_length_in_bytes_Zr(pairing);
    g2_buf = (char *)malloc(g2_len);
    zr_buf = (char *)malloc(zr_len);

    element_init_G2(Ca, pairing);
    element_init_G2(g, pairing);
    element_init_G2(pk, pairing);
    element_init_Zr(sk, pairing);
    mpz_init(N);
    mpz_init(pi);
    mpz_init(e);
    mpz_init(d);
    mpz_init(phi_N);

    if ((fp = fopen("keyword.txt", "r"))== NULL) {
        printf("Please provide at least 1000 keywords in a file named \'keyword.txt\'.\n");
        return STS_ERR;
    }
    for(int i = 0; i < 1000; i++) {
        if(fscanf(fp, "%s", w) != EOF) {
            strcpy(dataset[i], w);
        }else {
            printf("Error!\n");
            break;
        }
    }
    fclose(fp);

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

    cost1 = 0.0;
    printf("Time cost of DEKS encryption with T=2^0:(ms)\n");
    gettimeofday(&start, NULL);
    for(int i = 0; i < 1000; i++) {
        deks_encrypt(Ca, Cb, 0, pairing, g, pk, N, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost1 += time_cost(start, end);
            printf("%9.3f\n", cost1);
            gettimeofday(&start, NULL);
        }
    }
    printf("avg-%.3f\n", cost1/1000);

    cost1 = 0.0;
    printf("Time cost of DEKS encryption with T=2^12:(ms)\n");
    gettimeofday(&start, NULL);
    for(int i = 0; i < 1000; i++) {
        deks_encrypt(Ca, Cb, 12, pairing, g, pk, N, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost1 += time_cost(start, end);
            printf("%9.3f\n", cost1);
            gettimeofday(&start, NULL);
        }
    }
    printf("avg-%.3f\n", cost1/1000);

    cost1 = 0.0;
    printf("Time cost of DEKS encryption with T=2^24:(ms)\n");
    gettimeofday(&start, NULL);
    for(int i = 0; i < 50; i++) {
        deks_encrypt(Ca, Cb, 24, pairing, g, pk, N, dataset[i]);
    }
    gettimeofday(&end, NULL);
    cost1 = time_cost(start, end);
    printf("%.3f\n", cost1);
    printf("avg-%.3f\n", cost1/50);

    cost2 = 0.0;
    printf("Time cost of PEKS encryption:(ms)\n");
    gettimeofday(&start, NULL);
    for(int i = 0; i < 1000; i++) {
        peks_encrypt(Ca, Cb, pairing, g, pk, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost2 += time_cost(start, end);
            printf("%9.3f\n", cost2);
            gettimeofday(&start, NULL);
        }
    }
    printf("avg-%.3f\n", cost2/1000);

    cost3 = 0.0;
    printf("Time cost of SA-PEKS encryption:(ms)\n");
    gettimeofday(&start, NULL);
    for(int i = 0; i < 1000; i++) {
        sa_peks_encrypt(Ca, Cb, pairing, g, pk, N, e, d, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost3 += time_cost(start, end);
            printf("%9.3f\n", cost3);
            gettimeofday(&start, NULL);
        }
    }
    printf("avg-%.3f\n", cost3/1000);

    printf("Time cost of DEKS encryption with various T and average KGA: without-/with-catalyst,Enron,Wikipedia(ms,ms,h,h)\n");
    for (int i = 0; i < 29; ++i) {
        catalyst_gen(i, phi_N, pi);
        gettimeofday(&start, NULL);
        for (int j = 0; j < 100; ++j) {
            deks_encrypt(Ca, Cb, i, pairing, g, pk, N, dataset[j]);
        }
        gettimeofday(&end, NULL);
        cost1 = time_cost(start, end);
        gettimeofday(&start, NULL);
        for (int j = 0; j < 100; ++j) {
            deks_encrypt_catalyst(Ca, Cb, i, pairing, g, pk, pi, N, dataset[j]);
        }
        gettimeofday(&end, NULL);
        cost3 = time_cost(start, end);
        printf("%2d\t%10.3f\t%5.3f", i, cost1/100, cost3/100); // without/with catalyst

        if (i > 9) {
            kga_cost = cost1/100 + TEST_COST;
            result = 0.0;
            for (int j = 1; j <= 400087; ++j) { // Enron dataset
                result += kga_cost * j;
            }
            printf("\t%8.3f", result/400087/3600000);
            result = 0.0;
            if (i < 25) {
                for (int j = 1; j <= 6756439; ++j) { // Wikipedia dataset
                    result += kga_cost * j;
                }
                printf("\t%8.3f", result/6756439/3600000);
            }else {
                printf("\t-----.---");
            }
        } else {
            printf("\t-----.---\t-----.---");
        }
        printf("\n");
    }

    printf("Time cost of PEKS average KGA: Enron,Wikipedia(min,min)\n");
    kga_cost = cost2/1000 + TEST_COST;
    result = 0.0;
    for (int i = 1; i <= 400087; ++i) {
        result += kga_cost * i;
    }
    printf("%7.3f", result/400087/60000);
    result = 0.0;
    for (int i = 1; i <= 6756439; ++i) {
        result += kga_cost * i;
    }
    printf("\t%7.3f\n", result/6756439/60000);

    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    element_clear(Ca);
    mpz_clear(N);
    mpz_clear(pi);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(phi_N);
    pairing_clear(pairing);

    return STS_OK;
}