# Generate parameters and some keyword-searchable ciphertexts, store them
gcc -o benchmark_params_ciphers benchmark_params_ciphers.c deks.h deks.c peks.h peks.c sa_peks.h sa_peks.c -lpbc -lgmp -lcrypto
./benchmark_params_ciphers
# Evaluate Algorithm Trapdoor and the generation of catalyst
gcc -o benchmark_trapgen benchmark_trapgen.c deks.h deks.c peks.h peks.c sa_peks.h sa_peks.c -lpbc -lgmp -lcrypto
./benchmark_trapgen
# Evaluate Algorithm Test
gcc -o benchmark_test benchmark_test.c deks.h deks.c peks.h peks.c sa_peks.h sa_peks.c -lpbc -lgmp -lcrypto
./benchmark_test
# Evaluate Encryption, estimate KGA on Wikipedia and Enron datasets
gcc -o benchmark_encryption benchmark_encryption.c deks.h deks.c peks.h peks.c sa_peks.h sa_peks.c -lpbc -lgmp -lcrypto
./benchmark_encryption
# Generate and Test a Ciphertext in Parallel
gcc -o benchmark_gen_test_multithread benchmark_gen_test_multithread.c deks.h deks.c -lpbc -lgmp -lcrypto -lpthread
./benchmark_gen_test_multithread
# Evaluate Algorithm Setup
gcc -o benchmark_setup benchmark_setup.c deks.h deks.c peks.h peks.c sa_peks.h sa_peks.c -lpbc -lgmp -lcrypto
./benchmark_setup