#include "deks.h"
#include "peks.h"
#include "sa_peks.h"
// Save parameters and keyword-searchable ciphertexts

char dataset[1024][64];

int main(int argc, char * argv[]) {
    
	char * ec_param = "type f\nq 16283262548997601220198008118239886027035269286659395419233331082106632227801\nr 16283262548997601220198008118239886026907663399064043451383740756301306087801\nb 7322757890651446833342173470888950103129198494728585151431956701557392549679\nbeta 9776063510951480907546829895586341975790848099009256891110816835958685274282\nalpha0 1776307819061905444848005605541335123416176649043693774569737527341520482926\nalpha1 4922472003107175314522406564324183657125055707028154503359780540299732014568";
    //Type-f BN256

    pairing_t pairing;
    element_t g, pk, sk, Ca;
    mpz_t N, e, d, phi_N, p, q, pi;
	char Cb[HASH_LEN];
	char w[64], tmp[8];
	int g2_len, zr_len;
	char * g2_buf, * zr_buf;
    FILE * fp;
    
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
    mpz_init(e);
    mpz_init(d);
	mpz_init(phi_N);
	mpz_init(pi);

    element_random(g);
    element_random(sk);
    element_pow_zn(pk, g, sk); // pk = g^sk

    mpz_init(p);
    mpz_init(q);
    mpz_set_str(p, "DD848D47E193DCF0F57DD9256ABF10B5869C2D5D600C21A4D36C29659C062542B5CDCB6CF1002D7177D720472078AFC0193BAD7E0FCE7C07CABC83526F71CF2881993188748C07C52CF73D1A09BF38F22163909A7EBAEEC9A9D9019F6CE919AEF18BCD995F80E7823370D500B53DC85D169F4FBA383C9A2E7DA2393A11A9B171C86957B82E8115F9FB19670466155E50E41ADF91FB392EBC53614A475F58F9959972E56346993923991BD15110D2393513243DFEB2C28FCDFA067535E7A8A4DF", 16);
    mpz_set_str(q, "F9CE5FD04C169FC42F3C24C9E149EDCA7513A02648628C9AB80A9E9CE6F1FCD7EF4EA0FBC5AD4BE3E2B199A99969B74901B46BAF632A3B653A2E0FDC37D9D44646247C104EAB0A38027725886DCCAC682A3E71A84F57E5CE3FAF8C6DD7DEA27207AD6B3FBDDD51A4898884FB9C4853826C2836987179D4359122308CC6D44987562800D136BFB01CB3611E66B0F862EFA0E3769BE3795A9A75CA36A69E60851111849F8F0B8D46C5ACE50FCA7157B48B991C5AE30BC7B4198C464302C477CD0F", 16);
    mpz_mul(N, p, q); // N = p * q

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi_N, p, q); // phi_N = (p-1) * (q-1)

    mpz_set_str(e, "10001", 16); // 65537
    mpz_invert(d, e, phi_N);

    // Save parameters
    if ((fp = fopen("params.txt", "wb")) == NULL) {
        printf("Error to create a new file!\n");
        return STS_ERR;
    }
    element_to_bytes_compressed(g2_buf, g);
    fwrite(g2_buf, g2_len, 1, fp);
    element_to_bytes_compressed(g2_buf, pk);
    fwrite(g2_buf, g2_len, 1, fp);
    element_to_bytes(zr_buf, sk);
    fwrite(zr_buf, zr_len, 1, fp);
    mpz_out_raw(fp, N);
    mpz_out_raw(fp, e);
    mpz_out_raw(fp, d);
    mpz_out_raw(fp, phi_N); // To compute catalyst
	fclose(fp);

	// Save keyword-searchable ciphertexts for testing
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

    if ((fp = fopen("CipherDEKS-0.txt", "wb")) == NULL) {
        printf("Error to create a new file!\n");
        return STS_ERR;
    }
    catalyst_gen(0, phi_N, pi);
    for(int i = 0; i < 1000; i++) {
        deks_encrypt_catalyst(Ca, Cb, 0, pairing, g, pk, pi, N, dataset[i]);
        element_to_bytes_compressed(g2_buf, Ca);
        fwrite(g2_buf, g2_len, 1, fp);
        fwrite(Cb, HASH_LEN, 1, fp);
    }
    fclose(fp);

    if ((fp = fopen("CipherDEKS-12.txt", "wb")) == NULL) {
        printf("Error to create a new file!\n");
        return STS_ERR;
    }
    catalyst_gen(12, phi_N, pi);
    for(int i = 0; i < 1000; i++) {
        deks_encrypt_catalyst(Ca, Cb, 12, pairing, g, pk, pi, N, dataset[i]);
        element_to_bytes_compressed(g2_buf, Ca);
        fwrite(g2_buf, g2_len, 1, fp);
        fwrite(Cb, HASH_LEN, 1, fp);
    }
    fclose(fp);

    if ((fp = fopen("CipherDEKS-24.txt", "wb")) == NULL) {
        printf("Error to create a new file!\n");
        return STS_ERR;
    }
    catalyst_gen(24, phi_N, pi);
    for(int i = 0; i < 1000; i++) {
        deks_encrypt_catalyst(Ca, Cb, 24, pairing, g, pk, pi, N, dataset[i]);
        element_to_bytes_compressed(g2_buf, Ca);
        fwrite(g2_buf, g2_len, 1, fp);
        fwrite(Cb, HASH_LEN, 1, fp);
    }
    fclose(fp);

    if ((fp = fopen("CipherPEKS.txt", "wb")) == NULL) {
        printf("Error to create a new file!\n");
        return STS_ERR;
    }
    for(int i = 0; i < 1000; i++) {
        peks_encrypt(Ca, Cb, pairing, g, pk, dataset[i]);
        element_to_bytes_compressed(g2_buf, Ca);
        fwrite(g2_buf, g2_len, 1, fp);
        fwrite(Cb, HASH_LEN, 1, fp);
    }
    fclose(fp);

    if ((fp = fopen("CipherSAPEKS.txt", "wb")) == NULL) {
        printf("Error to create a new file!\n");
        return STS_ERR;
    }
    for(int i = 0; i < 1000; i++) {
        sa_peks_encrypt(Ca, Cb, pairing, g, pk, N, e, d, dataset[i]);
        element_to_bytes_compressed(g2_buf, Ca);
        fwrite(g2_buf, g2_len, 1, fp);
        fwrite(Cb, HASH_LEN, 1, fp);
    }
    fclose(fp);

    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    element_clear(Ca);
	mpz_clear(phi_N);
    mpz_clear(N);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(pi);
    pairing_clear(pairing);

    return STS_OK;
}