#include "crypto.h"

// #define PBC_DEBUG

//   --------------------------------------------------- utility Functions  ---------------------------------------------------

unsigned char *element_to_bytes_array(element_t e)
{ // COMPRESS for efficient transmission (element_length_in_bytes_compressed)
    size_t len = element_length_in_bytes(e);
    unsigned char *str = (unsigned char *)malloc(len);
    element_to_bytes(str, e);
    return str;
}

unsigned char *element_to_hash(element_t e)
{
    size_t len = element_length_in_bytes(e);
    unsigned char *str = (unsigned char *)malloc(len);
    element_to_bytes(str, e);

    unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    SHA256(str, len, hash);
    free(str);
    return hash;
}

void element_to_hash_element(element_t e, element_t *h, pairing_t pairing)
{
    size_t len = element_length_in_bytes(e);
    unsigned char *str = (unsigned char *)malloc(len);
    element_to_bytes(str, e);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(str, len, hash);

    element_init_G1(*h, pairing);
    element_from_bytes(*h, hash);
}

//   --------------------------------------------------- Ciphertext - utilities  ---------------------------------------------------

void get_byte_arrays(const Ciphertext *ct,
                     unsigned char **c1,
                     unsigned char **c2,
                     unsigned char **c3,
                     unsigned char **c4,
                     unsigned char **c5)
{
    *c1 = ct->C1.data;
    *c2 = ct->C2.data;
    *c3 = ct->C3.data;
    *c4 = ct->C4.data;
    *c5 = ct->C5.data;
}

Ciphertext *create_ciphertext(
    unsigned char *c1, size_t c1_len,
    unsigned char *c2, size_t c2_len,
    unsigned char *c3, size_t c3_len,
    unsigned char *c4, size_t c4_len,
    unsigned char *c5, size_t c5_len)
{
    Ciphertext *ct = (Ciphertext *)malloc((sizeof(Ciphertext)));
    if (!ct)
        return NULL;

    // Allocate and initialize C1
    ct->C1.data = (unsigned char *)malloc(c1_len);
    if (!ct->C1.data)
    {
        free(ct);
        return NULL;
    }
    ct->C1.length = c1_len;
    memcpy(ct->C1.data, c1, c1_len);

    // Allocate and initialize C2
    ct->C2.data = (unsigned char *)malloc(c2_len);
    if (!ct->C2.data)
    {
        free(ct->C1.data);
        free(ct);
        return NULL;
    }
    ct->C2.length = c2_len;
    memcpy(ct->C2.data, c2, c2_len);

    // Allocate and initialize C3
    ct->C3.data = (unsigned char *)malloc(c3_len);
    if (!ct->C3.data)
    {
        free(ct->C2.data);
        free(ct->C1.data);
        free(ct);
        return NULL;
    }
    ct->C3.length = c3_len;
    memcpy(ct->C3.data, c3, c3_len);

    // Allocate and initialize C4
    ct->C4.data = (unsigned char *)malloc(c4_len);
    if (!ct->C4.data)
    {
        free(ct->C3.data);
        free(ct->C2.data);
        free(ct->C1.data);
        free(ct);
        return NULL;
    }
    ct->C4.length = c4_len;
    memcpy(ct->C4.data, c4, c4_len);

    // Allocate and initialize C5
    ct->C5.data = (unsigned char *)malloc(c5_len);
    if (!ct->C5.data)
    {
        free(ct->C4.data);
        free(ct->C3.data);
        free(ct->C2.data);
        free(ct->C1.data);
        free(ct);
        return NULL;
    }
    ct->C5.length = c5_len;
    memcpy(ct->C5.data, c5, c5_len);

    return ct;
}

SerializedCiphertext *serialize_ciphertext(const Ciphertext *ct)
{
    size_t total_length = 0,
           c1_len = ct->C1.length,
           c2_len = ct->C2.length,
           c3_len = ct->C3.length,
           c4_len = ct->C4.length,
           c5_len = ct->C5.length;

    total_length = c1_len + c2_len + c3_len + c4_len + c5_len;

    size_t metadata_size = 5 * sizeof(size_t);
    size_t buffer_size = metadata_size + total_length;

    SerializedCiphertext *ser_ct = (SerializedCiphertext *)malloc(sizeof(SerializedCiphertext));
    if (!ser_ct)
        return NULL;

    ser_ct->buffer = (unsigned char *)malloc(buffer_size);
    if (!ser_ct->buffer)
    {
        free(ser_ct);
        return NULL;
    }
    ser_ct->total_length = buffer_size;

    size_t *length_ptr = (size_t *)ser_ct->buffer;
    length_ptr[0] = c1_len;
    length_ptr[1] = c2_len;
    length_ptr[2] = c3_len;
    length_ptr[3] = c4_len;
    length_ptr[4] = c5_len;

    unsigned char *data_ptr = ser_ct->buffer + metadata_size;

    memcpy(data_ptr, ct->C1.data, c1_len);
    data_ptr += c1_len;
    memcpy(data_ptr, ct->C2.data, c2_len);
    data_ptr += c2_len;

    memcpy(data_ptr, ct->C3.data, c3_len);
    data_ptr += c3_len;

    memcpy(data_ptr, ct->C4.data, c4_len);
    data_ptr += c4_len;

    memcpy(data_ptr, ct->C5.data, c5_len);

    return ser_ct;
}

Ciphertext *deserialize_ciphertext(const SerializedCiphertext *ser_ct)
{
    if (!ser_ct || !ser_ct->buffer)
        return NULL;

    size_t *length_ptr = (size_t *)ser_ct->buffer;
    size_t c1_len = length_ptr[0];
    size_t c2_len = length_ptr[1];
    size_t c3_len = length_ptr[2];
    size_t c4_len = length_ptr[3];
    size_t c5_len = length_ptr[4];

    Ciphertext *ct = (Ciphertext *)malloc(sizeof(Ciphertext));
    if (!ct)
        return NULL;

    size_t metadata_size = 5 * sizeof(size_t);
    unsigned char *data_ptr = ser_ct->buffer + metadata_size;

    ct->C1.data = (unsigned char *)malloc(c1_len);
    ct->C1.length = c1_len;
    memcpy(ct->C1.data, data_ptr, c1_len);
    data_ptr += c1_len;

    ct->C2.data = (unsigned char *)malloc(c2_len);
    ct->C2.length = c2_len;
    memcpy(ct->C2.data, data_ptr, c2_len);
    data_ptr += c2_len;

    ct->C3.data = (unsigned char *)malloc(c3_len);
    ct->C3.length = c3_len;
    memcpy(ct->C3.data, data_ptr, c3_len);
    data_ptr += c3_len;

    ct->C4.data = (unsigned char *)malloc(c4_len);
    ct->C4.length = c4_len;
    memcpy(ct->C4.data, data_ptr, c4_len);
    data_ptr += c4_len;

    ct->C5.data = (unsigned char *)malloc(c5_len);
    ct->C5.length = c5_len;
    memcpy(ct->C5.data, data_ptr, c5_len);

    return ct;
}

void free_serialized_ciphertext(SerializedCiphertext *ser_ct)
{
    if (ser_ct)
    {
        if (ser_ct->buffer)
            free(ser_ct->buffer);
        free(ser_ct);
    }
}

void free_ciphertext(Ciphertext *ct)
{
    if (ct)
    {
        if (ct->C1.data)
            free(ct->C1.data);
        if (ct->C2.data)
            free(ct->C2.data);
        if (ct->C3.data)
            free(ct->C3.data);
        if (ct->C4.data)
            free(ct->C4.data);
        if (ct->C5.data)
            free(ct->C5.data);
        free(ct);
    }
}

//   --------------------------------------------------- Initialize   ---------------------------------------------------

void initialize(int lambda, int n, int data_classes,
                pbc_param_t *param,
                pairing_t *pairing,
                element_t *g,
                element_t g_values[])
{

    // // FILE based params [comment if using custom]
    // FILE *fptr = fopen("./params/a.param", "r");
    // if (!fptr)
    // {
    //     perror("Failed to open parameter file");
    //     exit(1);
    // }

    // fseek(fptr, 0, SEEK_END);
    // long file_size = ftell(fptr);
    // fseek(fptr, 0, SEEK_SET);

    // char *buffer = (char *)malloc(file_size);
    // if (!buffer)
    // {
    //     printf("Memory allocation failed");
    //     exit(1);
    // }

    // fread(buffer, 1, file_size, fptr);

    // fclose(fptr);

    // // Select bilinear groups G1 and GT
    // pairing_init_set_buf(*pairing, buffer, file_size);

    // CUSTOM Parameter Generation [uncomment as an alternative for file based params]
    int rbits = lambda, qbits = 2 * lambda;

    pbc_param_init_a_gen(*param, rbits, qbits);
     //   pbc_param_clear(param);

    // Select bilinear groups G1 and GT
    pairing_init_pbc_param(*pairing, *param); // with prime order p : 2^λ ≤p ≤ 2^λ+1

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

        int index = n / 2 + j - 1;
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
        int index = (n + 1 - a - 1);
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

    element_pow_zn(pub[1], g_values[data_classes - 1], r);

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
    // element_clear(s);
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

const SerializedCiphertext *enc(int data_class,
                                int n, int data_classes,
                                element_t mpk,
                                element_t g,
                                element_t g_values[],
                                pairing_t pairing,
                                element_t dynK,
                                unsigned char *plaintext)
{
    if (data_class >= n / 2 || data_class < 0)
    {
        printf("Error: Invalid data class\n");
        return NULL;
    }

    // Initialize elements
    element_t t, R2;
    element_init_Zr(t, pairing);
    element_init_GT(R2, pairing);

    // Random values
    element_random(t);
    element_random(R2);

    // Generate actual ciphertext components
    // C1 = g^t
    element_t c1;
    element_init_G1(c1, pairing);
    element_pow_zn(c1, g, t);
    size_t c1_len = element_length_in_bytes(c1);
    unsigned char *C1 = (unsigned char *)pbc_malloc(c1_len);
    element_to_bytes(C1, c1);
    element_clear(c1);

    // C2 = (mpk * g_i)^t
    element_t c2, temp;
    element_init_G1(c2, pairing);
    element_init_G1(temp, pairing);
    element_mul(temp, mpk, g_values[data_class - 1]);
    element_pow_zn(c2, temp, t);
    size_t c2_len = element_length_in_bytes(c2);
    unsigned char *C2 = (unsigned char *)pbc_malloc(c2_len);
    element_to_bytes(C2, c2);
    element_clear(c2);
    element_clear(temp);

    // C3 = R2 * e(g1, gn)^t
    element_t c3, e_result;
    element_init_GT(c3, pairing);
    element_init_GT(e_result, pairing);
    element_pairing(e_result, g_values[0], g_values[n - 1]);
    element_pow_zn(e_result, e_result, t);
    element_mul(c3, R2, e_result);
    size_t c3_len = element_length_in_bytes(c3);
    unsigned char *C3 = (unsigned char *)pbc_malloc(c3_len);
    element_to_bytes(C3, c3);
    element_clear(c3);
    element_clear(e_result);

    // C4 = dynK^t
    element_t c4;
    element_init_G1(c4, pairing);
    element_pow_zn(c4, dynK, t);
    size_t c4_len = element_length_in_bytes(c4);
    unsigned char *C4 = (unsigned char *)pbc_malloc(c4_len);
    element_to_bytes(C4, c4);
    element_clear(c4);

    // C5 = M ⊕ H(R2)
    unsigned char *hash = element_to_hash(R2);
    size_t plaintext_len = strlen(plaintext);
    unsigned char *C5 = (unsigned char *)pbc_malloc(plaintext_len + 1);

    for (size_t i = 0; i < plaintext_len; i++)
    {
        *(C5 + i) = plaintext[i] ^ hash[i % SHA256_DIGEST_LENGTH];
    }
    *(C5 + plaintext_len) = '\0';

    //  create ciphertext
    Ciphertext *ct = create_ciphertext(C1, c1_len, C2, c2_len, C3, c3_len, C4, c4_len, C5, plaintext_len);
    pbc_free(C1);
    pbc_free(C2);
    pbc_free(C3);
    pbc_free(C4);
    pbc_free(C5);

    SerializedCiphertext *ser_ct = serialize_ciphertext(ct);
    free_ciphertext(ct);
    // Clean up main elements
    element_clear(t);
    element_clear(R2);
    free(hash);

    return ser_ct;
} //   --------------------------------------------------- Decryption   ---------------------------------------------------

unsigned char *dec(int n, int data_classes,
                   int data_class,
                   element_t k_u,
                   element_t pub[],
                   int auth[],
                   element_t g_values[],
                   pairing_t pairing,
                   const SerializedCiphertext *ser_ct)
{
    unsigned char *C1, *C2, *C3, *C4, *C5;
    element_t A, B;
    element_init_GT(A, pairing);
    element_init_GT(B, pairing);
    Ciphertext *ct = deserialize_ciphertext(ser_ct);
    if (!ct)
    {
        element_clear(A);
        element_clear(B);
        return NULL;
    }
    get_byte_arrays(ct, &C1, &C2, &C3, &C4, &C5);
    // Computing A = C3 * e(pub1 * ∏(gn+1-a+i), C1) / e(C2, ∏(gn+1-a))
    element_t numerator, denominator, temp1, temp2, c1_elem, c2_elem, c3_elem;
    element_init_GT(numerator, pairing);
    element_init_GT(denominator, pairing);
    element_init_GT(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_G1(c1_elem, pairing);
    element_init_G1(c2_elem, pairing);
    element_init_GT(c3_elem, pairing);

    // Convert bytes back to elements
    element_from_bytes(c1_elem, ct->C1.data);
    element_from_bytes(c2_elem, ct->C2.data);
    element_from_bytes(c3_elem, ct->C3.data);

    // Calculate ∏(gn+1-a+i) for a ∈ Auth(u) where a ≠ i
    element_t auth_product;
    element_init_G1(auth_product, pairing);
    element_set1(auth_product);
    for (int a = 0; a < n / 2; a++)
    {
        if (auth[a] == 0 || a == data_class)
            continue;
        int index = n + 1 - a + data_class - 1;
        if (index < n * 2)
        {
            element_mul(auth_product, auth_product, g_values[index]);
        }
    }

    // Calculate numerator
    element_mul(temp2, pub[0], auth_product);
    element_pairing(temp1, temp2, c1_elem);
    element_mul(numerator, c3_elem, temp1);

    // Calculate ∏(gn+1-a) for a ∈ Auth(u)
    element_set1(auth_product);
    for (int a = 0; a < n / 2; a++)
    {
        if (auth[a] == 0)
            continue;
        int index = n + 1 - a - 1;
        if (index < n * 2)
        {
            element_mul(auth_product, auth_product, g_values[index]);
        }
    }

    // Calculate denominator
    element_pairing(denominator, c2_elem, auth_product);

    // Compute A
    element_div(A, numerator, denominator);
    // Computing B = (pub4 * e(Ku, pub2) * e(∏∏(gn/2+1-b+j), pub2)) / e(pub3, ∏(gn/2+1-b))
    element_t B_num, B_denom;
    element_init_GT(B_num, pairing);
    element_init_GT(B_denom, pairing);

    // First part: pub4 * e(Ku, pub2)
    element_t temp3;
    element_init_GT(temp3, pairing);
    element_pairing(temp3, k_u, pub[1]);
    element_mul(B_num, pub[3], temp3);

    // Second part: Calculate double product term
    for (int j = 0; j < n / 2; j++)
    {
        if (auth[j] == 0)
            continue;
        element_t inner_product;
        element_init_G1(inner_product, pairing);
        element_set1(inner_product);

        for (int b = 0; b < n / 2; b++)
        {
            if (auth[b] == 0 || b == j)
                continue;
            int index = n / 2 + 1 - b + j - 1;
            if (index < n * 2)
            {
                element_mul(inner_product, inner_product, g_values[index]);
            }
        }

        element_t temp4;
        element_init_GT(temp4, pairing);
        element_pairing(temp4, inner_product, pub[1]);
        element_mul(B_num, B_num, temp4);

        element_clear(inner_product);
        element_clear(temp4);
    }

    // Calculate denominator term
    element_t denom_product;
    element_init_G1(denom_product, pairing);
    element_set1(denom_product);
    for (int b = 0; b < n / 2; b++)
    {
        if (auth[b] == 0)
            continue;
        int index = n / 2 + 1 - b - 1;
        if (index < n * 2)
        {
            element_mul(denom_product, denom_product, g_values[index]);
        }
    }
    element_pairing(B_denom, pub[2], denom_product);

    // Compute B
    element_div(B, B_num, B_denom);

    // Final decryption: M = H(A * e(pub5 * H(B)^-1, C4)^-1)^-1 ⊕ C5
    element_t h_B, combined, c4_elem;
    element_init_G1(h_B, pairing);
    element_init_G1(combined, pairing);
    element_init_G1(c4_elem, pairing);

    // Convert C4 back to element
    element_from_bytes(c4_elem, ct->C4.data);

    // Calculate H(B)^-1
    element_to_hash_element(B, &h_B, pairing);
    element_invert(h_B, h_B);

    // Combine with pub5
    element_mul(combined, pub[4], h_B);

    // Calculate pairing
    element_t pairing_result;
    element_init_GT(pairing_result, pairing);
    element_pairing(pairing_result, combined, c4_elem);
    element_invert(pairing_result, pairing_result);

    // Multiply with A
    element_mul(temp1, A, pairing_result);

    // Get final hash
    unsigned char *final_hash = element_to_hash(temp1);

    // XOR with C5 to get plaintext
    int cipher_len = ct->C5.length;
    unsigned char *M = (unsigned char *)pbc_malloc(cipher_len + 1);
    M[cipher_len] = '\0';

    for (int i = 0; i < cipher_len; i++)
    {
        M[i] = final_hash[i % SHA256_DIGEST_LENGTH] ^ ct->C5.data[i];
    }

    // Cleanup
    free_ciphertext(ct);
    free(final_hash);
    element_clear(A);
    element_clear(B);
    element_clear(numerator);
    element_clear(denominator);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(c1_elem);
    element_clear(c2_elem);
    element_clear(c3_elem);
    element_clear(auth_product);
    element_clear(B_num);
    element_clear(B_denom);
    element_clear(denom_product);
    element_clear(h_B);
    element_clear(combined);
    element_clear(c4_elem);
    element_clear(pairing_result);

    return M;
}
//   --------------------------------------------------- UpdateSet   ---------------------------------------------------

void updateSet(int data_class, int n, int data_classes, int auth[], int type, element_t *dynK, element_t msk[], element_t pub_u, element_t pub[], element_t mpk, element_t g, element_t g_values[], pairing_t pairing)
{
    auth[data_class] = type;

    element_t y2_;
    element_init_Zr(y2_, pairing);
    element_random(y2_);
    element_pow_zn(*dynK, g, y2_);

    element_set(msk[1], y2_);

    pub_extract(pairing, msk[0], mpk, *dynK, g, pub_u, pub, auth, g_values, n, data_classes);
    element_clear(y2_);
}
//   --------------------------------------------------- File Utils   ---------------------------------------------------
