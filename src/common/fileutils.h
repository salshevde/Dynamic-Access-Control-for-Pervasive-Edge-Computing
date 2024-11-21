#ifndef FILEUTILS_H
#define FILEUTILS_H
#include "cJSON.h"
#include "crypto.h"

char *read_file(const char *filename);
void write_file(const char *filename, const char *content);
void save_private_params(char *filename, element_t msk[]);

void load_private_params(char *filename, element_t msk[], pairing_t pairing);
void save_public_params(char *filename,
                        int lambda, int data_classes, int n,
                        pbc_param_t param,
                        element_t g, element_t g_values[],
                        element_t mpk, element_t dynK);
void load_public_params(char *filename,
                        int *lambda, int *data_classes, int *n,
                        pairing_t *pairing,
                        element_t *g, element_t g_values[],
                        element_t *mpk, element_t *dynK);

void save_user_params(char *filename,
                      pbc_param_t pairing, element_t pub_u, element_t pub[]);

void load_user_params(char *filename,
                      pairing_t pairing,
                      element_t *pub_u, element_t pub[]);
void store_aggkey(char *filename, element_t k_u);
void load_aggkey(char *filename, element_t *k_u, pairing_t pairing);

#endif