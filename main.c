#include <time.h>
#include <stdio.h>

#define PBC_DEBUG
#include <gmp.h>
#include <pbc/pbc.h>
#include <pbc/pbc_random.h>
#include <pbc/pbc_test.h>

#include <string.h>

#include <openssl/sha.h>
//   --------------------------------------------------- utility Functions  ---------------------------------------------------

unsigned char *element_to_bytes_array(element_t e)
{ // COMPRESS for efficient transmission (element_length_in_bytes_compressed)
    size_t len = element_length_in_bytes(e);
    unsigned char *str = (unsigned char *)pbc_malloc(len);
    element_to_bytes(str, e);
    return str;
}

unsigned char *element_to_hash(element_t e)
{
    size_t len = element_length_in_bytes(e);
    unsigned char *str = (unsigned char *)pbc_malloc(len);
    element_to_bytes(str, e);

    unsigned char *hash = (unsigned char *)pbc_malloc(SHA256_DIGEST_LENGTH);
    SHA256(str, len, hash);
    free(str);
    return hash;
}

void element_to_hash_element(element_t e, element_t *h, pairing_t pairing)
{
    size_t len = element_length_in_bytes(e);
    unsigned char *str = (unsigned char *)pbc_malloc(len);
    element_to_bytes(str, e);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(str, len, hash);

    element_init_G1(*h, pairing);
    element_from_bytes(*h, hash);
}

// element_t hash_to_element(unsigned char* hash,pairing_t pairing){

//     element_t h;
//     element_init_G1(h);
//     element_from_bytes(h,hash);
//     return h;
// }
//   --------------------------------------------------- Initialize   ---------------------------------------------------

void initialize(int lambda, int n, int data_classes,
                pbc_param_t param,
                pairing_t *pairing,
                element_t *g,
                // element_t H, // placeholder
                element_t g_values[])
{

    // FILE based params [comment if using custom]
    FILE *fptr = fopen("./a.param", "r");
    if (!fptr)
    {
        perror("Failed to open parameter file");
        exit(1);
    }

    fseek(fptr, 0, SEEK_END);
    long file_size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    char *buffer = (char *)pbc_malloc(file_size);
    if (!buffer)
    {
        printf("Memory allocation failed");
        exit(1);
    }

    fread(buffer, 1, file_size, fptr);

    fclose(fptr);

    // Select bilinear groups G1 and GT
    pairing_init_set_buf(*pairing, buffer, file_size);
    // CUSTOM Parameter Generation [uncomment as an alternative for file based params]
    // int rbits = lambda, qbits = 2 * lambda;

    // pbc_param_init_a_gen(param, rbits, qbits);

    // pbc_param_out_str(stdout, param); //FADDITIONAL:Add to file
    //     pbc_param_clear(param);

    // Select bilinear groups G1 and GT
    // pairing_init_pbc_param(*pairing, param); // with prime order p : 2^λ ≤p ≤ 2^λ+1

    if (!pairing_is_symmetric(*pairing))
        pbc_die("pairing must be symmetric");
    element_t a;
    // a generator g ∈ G1 at random
    element_init_G1(*g, *pairing);
    element_random(*g);

    // Choose random α ∈ Zp secretly
    element_init_Zr(a, *pairing);
    element_random(a);

    // for all i ∈ {1, 2, . . . , n, n+2, . . . , 2n}, **n = data_classes/2, 1-> 0 based indexing

    for (int i = 0; i < 2 * n; i++)
    {
        element_init_G1(g_values[i], *pairing);
        // if (i == n) // g_n+1 not defined -> 0
        // {

        //     element_set0(g_values[i]);
        //     continue;
        // }

        // α^i
        element_t a_i;
        element_init_Zr(a_i, *pairing);
        mpz_t i_mpz;
        mpz_init_set_ui(i_mpz, i + 1);
        element_pow_mpz(a_i, a, i_mpz);

        // compute gi = g^α^i

        element_t g_i;
        element_init_G1(g_i, *pairing);
        element_pow_zn(g_i, *g, a_i);

        element_set(g_values[i], g_i);

        // Clean up
        element_clear(a_i);
        element_clear(g_i);
        mpz_clear(i_mpz);
    }
    // and remove α.
    element_clear(a);

    // Select TCR H: GT->G1
    // element_t h;
    // element_init_G1(h, pairing);
    // element_from_hash(element_t e, void *data, int len);
    // Store params ← g, p, G1, GT, H, g1, GT, . . . , gn, gn+2, gn+3, . . . , GTn
}

//   ---------------------------------------------------  GEN   ---------------------------------------------------
void gen(
    pairing_t pairing,
    element_t g,
    element_t msk[],
    element_t *mpk,
    element_t *dynK)
{

    // – Select two numbers γ1, γ2 ∈ Zp uniformly at random.
    element_t y1, y2;
    element_init_Zr(y1, pairing);
    element_init_Zr(y2, pairing);

    element_random(y1);
    element_random(y2);

    // – Store msk← {γ1, γ2}

    element_init_Zr(msk[0], pairing);
    element_set(msk[0], y1);

    element_init_Zr(msk[1], pairing);
    element_set(msk[1], y2);

    // mpk ← g^γ1

    element_init_same_as(*mpk, g);
    element_pow_zn(*mpk, g, y1);

    // dynK = g^y2

    element_init_same_as(*dynK, g);
    element_pow_zn(*dynK, g, y2);

    // cleanup
    element_clear(y1);
    element_clear(y2);
}

//   --------------------------------------------------- Extract   ---------------------------------------------------
void agg_extract(
    int n, int data_classes,
    int auth_u[],
    element_t g_values[],
    pairing_t pairing,
    element_t y1,
    element_t *k_u,
    element_t *pub_u)
{

    // Ku
    element_init_same_as(*k_u, g_values[0]);
    element_set1(*k_u);

    for (int i = 0; i < n / 2; i++)
    {
        if (auth_u[i] == 0)
            continue;

        int index = (n / 2) + 1 - i - 1;
        element_mul(*k_u, *k_u, g_values[index]);
    }

    element_pow_zn(*k_u, *k_u, y1);

    // pub_u
    element_set1(*pub_u);

    for (int j = 0; j < n / 2; j++)
    {
        if (auth_u[j] == 0)
            continue;

        int index = (n / 2) - 1 + j;

        element_mul(*pub_u, *pub_u, g_values[index]);
    }
}

void pub_extract(
    pairing_t pairing,
    element_t y1,
    element_t mpk,
    element_t dynK,
    element_t g,
    element_t pub_u,
    element_t pub[],
    int auth_u[],
    element_t g_values[],
    int n, int data_classes)
{
    element_t r, s, R1;

    // Choose random values r, s $ ← Zp,

    element_init_Zr(r, pairing);
    element_random(r);
    element_init_Zr(s, pairing);
    element_random(s);

    // another random value R1 $ ← GT
    element_init_GT(R1, pairing);
    element_random(R1);

    //  compute the public parameters pub(u) = (pub1, . . . , pub5) corresponding to the aggregate key Ku as follows:

    // pub1
    element_t pub1_temp, x;

    element_init_same_as(pub1_temp, pub[0]);
    element_init_same_as(x, dynK);

    element_set1(pub1_temp);

    //  pi (g (n+1-a))
    for (int a = 0; a < n / 2; a++)
    {
        if (auth_u[a] == 0)
            continue;
        int index = (n + 1 - 1 - a);
        element_mul(pub1_temp, pub1_temp, g_values[index]); //(g (n+1-a))
    }

    //( pi (g (n+1-a))) ^y1
    element_pow_zn(pub1_temp, pub1_temp, y1);

    // (dynK)^s
    element_pow_zn(x, dynK, s);

    // pub1 =( pi (g (n+1-a))) ^y1.dynk^s
    element_mul(pub[0], pub1_temp, x);

    element_clear(pub1_temp);
    element_clear(x);

    // pub2    = (gn/2)^r

    element_t pub2_temp;
    element_init_same_as(pub2_temp, pub[1]);
    element_pow_zn(pub[1], g_values[n / 2 - 1], r);
    element_clear(pub2_temp);

    // pub3  = (mpk . pub0,u)^r
    element_t pub3_temp;
    element_init_same_as(pub3_temp, pub[2]);

    element_mul(pub3_temp, mpk, pub_u);   // mpk . pub0,u
    element_pow_zn(pub[2], pub3_temp, r); //  (mpk . pub0,u)^r

    element_clear(pub3_temp);

    // pub4 = R1.e(g1, gn)^r
    element_t pub4_temp;
    element_init_same_as(pub4_temp, pub[3]);
    element_init_GT(x, pairing);

    // e(g1, gn)
    element_pairing(x, g_values[0], g_values[n - 1]);

    //  e(g1, gn)^r
    element_pow_zn(x, x, r);

    // R1.e(g1, gn)^r
    element_mul(pub[3], x, R1);

    element_clear(pub4_temp);
    element_clear(x);

    // pub5 =  g^s.H(R1)

    element_t pub5_temp, x1, x2;
    element_init_same_as(pub5_temp, pub[4]);
    element_init_G1(x1, pairing);
    element_init_GT(x2, pairing);
    //  g^s
    element_pow_zn(x1, g, s);

    // H(R1)
    element_t h;
    element_to_hash_element(R1, &h, pairing);

    element_mul(pub[4], x1, h); // g^s.H(R1)

    element_clear(pub5_temp);
    element_clear(x1);
    element_clear(x2);
    element_clear(h);

    element_clear(r);
    element_clear(s);
    element_clear(R1);
}

void extract(pairing_t pairing,
             element_t msk[],
             element_t mpk,
             element_t dynK,
             element_t g,
             int auth_u[],
             element_t g_values[],
             int n, int data_classes,
             element_t *k_u,
             element_t *pub_u,
             element_t pub[])
{
    element_init_G1(*pub_u, pairing);
    for (int i = 0; i < 5; i++)
    {
        // element_init_Zr(pub[i] ,pairing);
        if (i == 3)
            element_init_GT(pub[i], pairing);
        else
            element_init_G1(pub[i], pairing);
    }

    agg_extract(n, data_classes, auth_u, g_values, pairing, msk[0], k_u, pub_u);
    pub_extract(pairing, msk[0], mpk, dynK, g, *pub_u, pub, auth_u, g_values, n, data_classes);
}

//   --------------------------------------------------- Enc   ---------------------------------------------------
unsigned int enc(int data_class,
                 int n, int data_classes,
                 element_t mpk,
                 element_t g,
                 element_t g_values[],
                 pairing_t pairing,
                 element_t dynK,
                 unsigned char *plaintext,
                 unsigned char *ciphertext,
                 unsigned char **C1, unsigned char **C2, unsigned char **C3, unsigned char **C4, unsigned char **C5)
{
    element_t t, R2;

    // Choose a random value t$← Zp,
    element_init_Zr(t, pairing);
    element_random(t);

    // Zp, a random value R2$← GT
    element_init_GT(R2, pairing);
    element_random(R2);

    // C1 = g^t
    element_t c, temp;
    element_init_G1(c, pairing);
    element_pow_zn(c, g, t);

    *C1 = element_to_bytes_array(c);
    element_clear(c);

    // C2 = (mpk.gi)^t
    element_init_same_as(c, g_values[data_class]);
    element_mul(c, mpk, g_values[data_class]);
    element_pow_zn(c, c, t);
    *C2 = element_to_bytes_array(c);
    element_clear(c);

    // C3 = R2.e(g1, gn)^t
    element_init_GT(c, pairing);
    element_init_GT(temp, pairing);
    element_pairing(temp, g_values[0], g_values[n - 1]); // e(g1, gn)
    element_pow_zn(temp, temp, t);                       // e(g1, gn)^t
    element_mul(c, R2, temp);                            // R2.e(g1, gn)^t
    *C3 = element_to_bytes_array(c);
    element_clear(temp);

    // C4 = (dynK)^t
    element_init_same_as(c, dynK);
    element_pow_zn(c, dynK, t);
    *C4 = element_to_bytes_array(c);
    element_clear(c);

    // C5 = M ⊕ H(R2)
    unsigned char *hash = element_to_hash(R2);
    *C5 = (unsigned char *)pbc_malloc(strlen(plaintext) + 1);
    strcpy(*C5, plaintext);
    int M_len = strlen(*C5);
    printf("\nEncrypted text: \n");
    for (int i = 0; i < M_len; i++)
    {
        (*C5)[i] = (*C5)[i] ^ hash[i % SHA256_DIGEST_LENGTH];
        printf("%c", (*C5)[i]);
    }
    printf("\n");

    // Ciphertext [for production]
    // unsigned int total_length = c1_length + c2_length + c3_length + c4_length + M_len;
    // ciphertext = (unsigned char *)malloc(total_length * sizeof(unsigned char)); // allocate memory for ciphertext
    // unsigned int offset = 0;
    // memcpy(ciphertext + offset, *C1, c1_length);
    // offset += c1_length;
    // memcpy(ciphertext + offset, *C2, c2_length);
    // offset += c2_length;
    // memcpy(ciphertext + offset, *C3, c3_length);
    // offset += c3_length;
    // memcpy(ciphertext + offset, *C4, c4_length);
    // offset += c4_length;
    // memcpy(ciphertext + offset, *C5, M_len);
    // offset += M_len;

    // Clean Up
    element_clear(t);
    element_clear(R2);

    return 1;
}

//   --------------------------------------------------- Decryption   ---------------------------------------------------

void dec(int n, int data_classes, int data_class, element_t k_u, element_t pub[], int auth[], element_t g_values[], pairing_t pairing, unsigned char *C1, unsigned char *C2, unsigned char *C3, unsigned char *C4, unsigned char *C5)
{
    element_t A, B;
    element_init_GT(A, pairing);

    element_t w, x, y, z, t1;

    // Computing A
    element_init_GT(t1, pairing);
    // A= NUMERATOR
    // C3.e(pub1 . a∈Auth(u)a!=i gn+1−a+i, C1)
    element_init_GT(w, pairing);
    element_init_GT(x, pairing);
    element_init_G1(y, pairing);
    element_init_G1(z, pairing);

    element_from_bytes(z, C1);
    element_from_bytes(w, C3);

    // a∈Auth(u)a!=i gn+1−a+i
    element_set(y, pub[0]);
    for (int a = 0; a < n / 2; a++)
    {
        if (auth[a] == 0 || a == data_class)
            continue;
        int index = n + 1 - a + data_class - 1;
        element_mul(y, y, g_values[a]);
    }

    // e(pub1 . a∈Auth(u)a!=i gn+1−a+i, C1)
    element_pairing(x, y, z);

    // C3.e
    element_mul(t1, w, x);

    element_clear(x);
    element_clear(y);
    element_clear(w);
    element_clear(z);
    // w = DENOMINATOR
    element_init_GT(w, pairing);
    element_init_same_as(x, g_values[data_class]);
    element_from_bytes(x, C2);
    element_init_G1(y, pairing);
    element_set1(y);

    // a∈Auth(u)gn+1−a
    for (int a = 0; a < n / 2; a++)
    {
        if (auth[a] == 0)
            continue;
        int index = n + 1 - a - 1;
        element_mul(y, y, g_values[a]);
    }

    // e(C2,Qa∈Auth(u)gn+1−a)
    element_pairing(w, x, y);

    element_div(A, t1, w);
    element_clear(x);
    element_clear(y);
    element_clear(w);

    // Computing B
    element_init_GT(B, pairing);
    element_init_GT(w, pairing);
    element_init_GT(x, pairing);
    // w= NUMERATOR
    // w= pub4.e(Ku, pub2)
    element_pairing(x, k_u, pub[1]);

    element_mul(w, pub[3], x);
    element_clear(x);

    // y= 𝜫 j∈Auth(u) 𝜫 b∈Auth(u)b!=j gn/2+1−b+j
    element_init_GT(x, pairing);
    element_init_same_as(y, g_values[0]);
    element_set1(y);
    for (int j = 0; j < n / 2; j++)
    {
        if (auth[j] == 0)
            continue;
        element_init_same_as(z, g_values[0]);
        element_set1(z);
        for (int b = 0; b < n / 2; b++)
        {
            if (auth[b] == 0 || b == j)
                continue;
            int index = n / 2 + 1 - b + j - 1;
            element_mul(z, z, g_values[index]);
        }

        element_mul(y, y, z);
        element_clear(z);
    }

    // x = e(𝜫 j∈Auth(u) 𝜫 b∈Auth(u)b!=j gn/2+1−b+j, pub2)
    element_pairing(x, y, pub[1]);
    element_mul(w, w, x);

    element_clear(x);
    element_clear(y);

    // x = Denominator
    element_init_GT(x, pairing);
    element_init_G1(y, pairing);

    // 𝜫 (gn/2+1−b)
    element_set1(y);
    for (int b = 0; b < n / 2; b++)
    {
        if (auth[b] == 0)
            continue;
        int index = n / 2 + 1 - b - 1;
        element_mul(y, y, g_values[index]);
    }

    element_pairing(x, pub[2], y);

    element_div(B, w, x);

    element_clear(w);
    element_clear(y);
    element_clear(x);

    // MESSAGE : M = H(A.e(pub5.(H(B))−1, C4)−1)−1⊕ C5.

    // pub5.(H(B))−1
    element_init_G1(w, pairing);

    element_to_hash_element(B, &w, pairing);

    element_invert(w, w);

    element_mul(w, w, pub[4]);

    // A.e(pub5.(H(B))−1, C4)−1
    element_init_G1(y, pairing);
    element_init_GT(x, pairing);
    element_init_GT(z, pairing);

    element_from_bytes(y, C4);

    element_pairing(x, w, y);
    element_invert(x, x);
    element_mul(z, A, x);

    element_clear(w);
    element_clear(y);
    element_clear(x);

    // H(A.e(pub5.(H(B))−1, C4)−1)-1
    element_init_G1(w, pairing);
    element_to_hash_element(z, &w, pairing);
    element_invert(w, w); // invert hash

    // element-> bytes for xor
    char *inv_hash = element_to_bytes_array(w);

    //
    int cipher_len = strlen(C5); // technicall should be equal to dec-len

    unsigned char *M = (unsigned char *)pbc_malloc(cipher_len);
    // if (cipher_len != inv_hash_len) {
    //     fprintf(stderr, "Error:%d %dMismatched lengths between inv_hash and C5.\n", cipher_len,inv_hash_len);
    //     return;
    // }

    printf("\nDecrypted Message: \n");
    for (int i = 0; i < cipher_len; i++)
    {

        M[i] = inv_hash[i] ^ C5[i];

        printf("%c", M[i]);
    }

    printf("\n");
    // return M;
}

//   --------------------------------------------------- UpdateSet   ---------------------------------------------------
// void updateSet(int data_class, int auth[],int type,pairing_t pairing ,element_t g, element_t *dynk, element_t msk[], element_t mpk, ){
//     auth[data_class] = type==0?0:1; // update authorized set
//     element_t y2_;
//     element_init_Zr(y2_,pairing);
//     element_pow_zn(*dynk, g,y2_);
//     msk[1] = y2_;

//     pub_extract(pairing, msk[0], mpk, *dynK, g, *pub_u, pub, auth_u, g_values, n);

// }
//   --------------------------------------------------- Random   ---------------------------------------------------

void write_params_to_file(int lambda, int data_classes, element_t g, element_t k_u, element_t g_values[], element_t msk[2], element_t mpk, element_t dynK, element_t pub_u, element_t pub[])
{
    FILE *f_public = fopen("public.param", "w");
    FILE *f_private = fopen("private.param", "w");

    fprintf(f_private, "\n\ng: ");
    element_out_str(f_private, 10, g);

    for (int i = 0; i < 4 * data_classes; i++)
    {
        fprintf(f_private, "\ng_%d: ", i + 1);
        element_out_str(f_private, 10, g_values[i]);
    }

    fprintf(f_private, "\n\nmsk[0] (y1): ");
    element_out_str(f_private, 10, msk[0]);
    fprintf(f_private, "\nmsk[1] (y2): ");
    element_out_str(f_private, 10, msk[1]);

    fprintf(f_public, "\n\nmpk: ");
    element_out_str(f_public, 10, mpk);

    fprintf(f_private, "\n\npub_u: ");
    element_out_str(f_private, 10, pub_u);

    fprintf(f_public, "\n");
    for (int i = 0; i < 5; i++)
    {
        fprintf(f_public, "\npub_%d: ", i + 1);
        element_out_str(f_public, 10, pub[i]);
    }

    fprintf(f_public, "\n\nK_u: ");
    element_out_str(f_public, 10, k_u);

    fprintf(f_public, "\n\ndynK: ");
    element_out_str(f_public, 10, dynK);
    fprintf(f_public, "\n");
    fprintf(f_private, "\n");

    fclose(f_public);
    fclose(f_private);
}
//   --------------------------------------------------- MAIN   ---------------------------------------------------
int main()
{
    //  Parameters: Modify Acc to user needs
    int lambda = 1024, data_classes = 4, data_class = 2;

    int auth_u[] = {0, 1, 1, 0}, n = data_classes * 2; // data class group to be authorized

    unsigned char *plaintext = "this is a message in transmission", *ciphertext, *message, *C1, *C2, *C3, *C4, *C5;
    printf("\nPlaintext: %s\n",plaintext);
    // Variable init

    pbc_param_t param;
    pairing_t pairing;
    mpz_t p;
    element_t g, g_values[n * 2];

    element_t msk[2], mpk, dynK;
    element_t k_u, pub_u, pub[5];

    //  INITIALIZATION
    initialize(
        lambda,
        n, data_classes,
        param,
        &pairing,
        &g,
        // H, // placeholder
        g_values);

    //  GENERATION
    gen(pairing,
        g,
        msk,
        &mpk,
        &dynK);

    // EXTRACT

    extract(pairing,
            msk,
            mpk,
            dynK,
            g,
            auth_u,
            g_values,
            n, data_classes,
            &k_u,
            &pub_u, pub);

    //  ENCRYPTION
    enc(data_class,
        n, data_classes,
        mpk,
        g, g_values,
        pairing,
        dynK,
        plaintext,
        ciphertext,
        &C1, &C2, &C3, &C4, &C5);

    // DECRYPTION
    dec(n, data_classes,
        data_class,
        k_u,
        pub,
        auth_u,
        g_values,
        pairing,
        C1, C2, C3, C4, C5);

    // Store params
    write_params_to_file(lambda,
                         data_classes,
                         g,
                         k_u,
                         g_values,
                         msk,
                         mpk,
                         dynK,
                         pub_u, pub);
    // Clean up
    element_clear(g);

    for (int i = 0; i < data_classes * 4; i++)
    {
        element_clear(g_values[i]);
    }
    element_clear(msk[0]);
    element_clear(msk[1]);
    element_clear(mpk);
    element_clear(dynK);
    element_clear(k_u);
    element_clear(pub_u);

    for (int i = 0; i < 5; i++)
    {
        element_clear(pub[i]);
    }

    pairing_clear(pairing);

    return 0;
}
