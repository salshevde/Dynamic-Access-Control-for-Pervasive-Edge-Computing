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
#endif