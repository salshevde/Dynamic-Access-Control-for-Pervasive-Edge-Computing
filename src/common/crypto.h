#ifndef CRYPTO_H
#define CRYPTO_H
#include <time.h>
#include <stdio.h>

#include <gmp.h>
#include <pbc/pbc.h>
#include <pbc/pbc_random.h>

#include <string.h>

#include <openssl/sha.h>

//   --------------------------------------------------- utility Functions  ---------------------------------------------------

unsigned char *element_to_bytes_array(element_t e);

unsigned char *element_to_hash(element_t e);

void element_to_hash_element(element_t e, element_t *h, pairing_t pairing);

//   --------------------------------------------------- Ciphertext - utilities  ---------------------------------------------------
typedef struct
{
    unsigned char *data;
    size_t length;
} CipherComponent;

typedef struct
{
    CipherComponent C1;
    CipherComponent C2;
    CipherComponent C3;
    CipherComponent C4;
    CipherComponent C5;
} Ciphertext;

typedef struct
{
    unsigned char *buffer;
    size_t total_length;
} SerializedCiphertext;

void get_byte_arrays(const Ciphertext *ct,
                     unsigned char **c1,
                     unsigned char **c2,
                     unsigned char **c3,
                     unsigned char **c4,
                     unsigned char **c5);

Ciphertext *create_ciphertext(
    unsigned char *c1, size_t c1_len,
    unsigned char *c2, size_t c2_len,
    unsigned char *c3, size_t c3_len,
    unsigned char *c4, size_t c4_len,
    unsigned char *c5, size_t c5_len);

SerializedCiphertext *serialize_ciphertext(const Ciphertext *ct);

Ciphertext *deserialize_ciphertext(const SerializedCiphertext *ser_ct);

void free_serialized_ciphertext(SerializedCiphertext *ser_ct);
void free_ciphertext(Ciphertext *ct);

// Functions
void initialize(int lambda, int n, int data_classes,
                pbc_param_t *param,
                pairing_t *pairing,
                element_t *g,
                element_t g_values[]);

void gen(
    pairing_t pairing,
    element_t g,
    element_t msk[],
    element_t *mpk,
    element_t *dynK);

void agg_extract(
    int n, int data_classes,
    int auth_u[],
    element_t g_values[],
    pairing_t pairing,
    element_t y1,
    element_t *k_u,
    element_t *pub_u);

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
    int n, int data_classes);

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
             element_t pub[]);

const SerializedCiphertext *enc(int data_class,
                                int n, int data_classes,
                                element_t mpk,
                                element_t g,
                                element_t g_values[],
                                pairing_t pairing,
                                element_t dynK,
                                unsigned char *plaintext);

unsigned char *dec(int n, int data_classes, 
                    int data_class, 
                    element_t k_u, 
                    element_t pub[], 
                    int auth[],
                    element_t g_values[], 
                    pairing_t pairing, 
                    const SerializedCiphertext *ser_ct);
void updateSet(int data_class, int n, 
               int data_classes, int auth[], 
               int type, 
               element_t *dynK, 
               element_t msk[], 
               element_t pub_u, 
               element_t pub[], 
               element_t mpk, 
               element_t g, 
               element_t g_values[], 
               pairing_t pairing);


#endif