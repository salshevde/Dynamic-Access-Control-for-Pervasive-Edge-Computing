#include "../common/crypto.h"

unsigned char *dec(int n, int data_classes, 
                    int data_class, 
                    element_t k_u, 
                    element_t pub[], 
                    int auth[],
                    element_t g_values[], 
                    pairing_t pairing, 
                    const SerializedCiphertext *ser_ct);