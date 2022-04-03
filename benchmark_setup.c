#include "deks.h"
#include "peks.h"
#include "sa_peks.h"
#include <sys/time.h>

static double time_cost(struct timeval A, struct timeval B) {
    double res;
    res = (B.tv_sec - A.tv_sec) * 1000000 + B.tv_usec - A.tv_usec;
    return res / 1000;
}

int main() {
    pairing_t pairing;
    element_t g, pk, sk;
    mpz_t N, pi, e, d, phi_N;
    struct timeval start, end;
    double cost1, cost2, cost3;
    int T;

    mpz_init(N);
    mpz_init(pi);
    mpz_init(e);
    mpz_init(d);
    mpz_init(phi_N);

    gettimeofday(&start, NULL);
    for (int i = 0; i < 100; ++i) {
        peks_setup(256, pairing, g, pk, sk);
    }
    gettimeofday(&end, NULL);
    cost2 = time_cost(start, end);
    printf("PEKS_Setup:\t%.3f ms\n", cost2/100);

    gettimeofday(&start, NULL);
    for (int i = 0; i < 100; ++i) {
        sa_peks_setup(256, 3072, pairing, g, pk, sk, N, e, d);
    }
    gettimeofday(&end, NULL);
    cost3 = time_cost(start, end);
    printf("SA-PEKS_Setup:\t%.3f ms\n", cost3/100);

    for (T = 10; T < 25; ++T) {
        printf("---T=%2d---\n", T);
        gettimeofday(&start, NULL);
        deks_setup(256, 3072, T, pairing, g, pk, sk, N, pi, phi_N);
        gettimeofday(&end, NULL);
        printf("DEKS_Setup:\t%.3f ms\n", time_cost(start, end));

        gettimeofday(&start, NULL);
        for (int i = 0; i < 1000; ++i) {
            catalyst_gen(T, phi_N, pi);
        }
        gettimeofday(&end, NULL);
        printf("Catalyst_Gen:\t%.3f us\n", time_cost(start, end));
    }

    mpz_clear(N);
    mpz_clear(pi);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(phi_N);

    return STS_OK;
}
