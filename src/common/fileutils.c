#include "fileutils.h"
//  File -> string
char *read_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = (char *)malloc(length + 1);
    if (content == NULL)
    {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);

    return content;
}

void write_file(const char *filename, const char *content)
{
    FILE *file = fopen(filename, "w");
    if (file == NULL)
    {
        perror("Error opening file for writing");
        return;
    }

    fprintf(file, "%s", content);
    fclose(file);
}

// PRIVATE

void save_private_params(char *filename, element_t msk[])
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "msk[0]", element_to_bytes_array(msk[0]));
    cJSON_AddStringToObject(json, "msk[1]", element_to_bytes_array(msk[1]));
    char *json_string = cJSON_Print(json);
    write_file(filename, json_string);
    cJSON_free(json_string);
    cJSON_Delete(json);
}

void load_private_params(char *filename, element_t msk[], pairing_t pairing)
{
    char *json_data = read_file(filename);
    cJSON *json = cJSON_Parse(json_data);
    free(json_data);

    cJSON *y1 = cJSON_GetObjectItemCaseSensitive(json, "msk[0]");
    element_init_Zr(msk[0], pairing);
    element_from_bytes(msk[0], y1->valuestring);
    cJSON *y2 = cJSON_GetObjectItemCaseSensitive(json, "msk[1]");
    element_init_Zr(msk[1], pairing);
    element_from_bytes(msk[1], y2->valuestring);
    cJSON_Delete(json);
}

//  Public
void save_public_params(char *filename,
                        int lambda, int data_classes, int n,
                        pbc_param_t param,
                        element_t g, element_t g_values[],
                        element_t mpk, element_t dynK)
{

    cJSON *json = cJSON_CreateObject();
    //  lambda
    cJSON_AddNumberToObject(json, "lambda", lambda);
    // n
    cJSON_AddNumberToObject(json, "n", n);

    //  data_classes
    cJSON_AddNumberToObject(json, "data_classes", data_classes);

    // param/ pairing
    char *param_string;
    size_t size;
    FILE *stream = open_memstream(&param_string, &size);
    pbc_param_out_str(stream, param);
    fclose(stream);
    cJSON_AddStringToObject(json, "param", param_string);
    free(param_string);
    // g
    char *value = element_to_bytes_array(g);
    cJSON_AddStringToObject(json, "g", value);

    // g_values
    for (int i = 0; i < 2 * n; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "g%d", i);
        value = element_to_bytes_array(g_values[i]);
        cJSON_AddStringToObject(json, key, value);
    }
    // mpk
    value = element_to_bytes_array(mpk);
    cJSON_AddStringToObject(json, "mpk", value);

    // dynK
    value = element_to_bytes_array(dynK);
    cJSON_AddStringToObject(json, "dynK", value);

    char *json_string = cJSON_Print(json);
    write_file(filename, json_string);

    free(value);
    cJSON_free(json_string);
    cJSON_Delete(json);
}

void load_public_params(char *filename,
                        int *lambda, int *data_classes, int *n,
                        pairing_t *pairing,
                        element_t *g, element_t g_values[],
                        element_t *mpk, element_t *dynK)
{
    char *json_data = read_file(filename);
    cJSON *json = cJSON_Parse(json_data);
    free(json_data);
    //     lambda
    cJSON *obj = cJSON_GetObjectItemCaseSensitive(json, "lambda");

    *lambda = obj->valuedouble;
    // n, data_classes

    obj = cJSON_GetObjectItemCaseSensitive(json, "n");

    *n = obj->valuedouble;

    obj = cJSON_GetObjectItemCaseSensitive(json, "data_classes");

    *data_classes = obj->valuedouble;
    // param/ pairing
    obj = cJSON_GetObjectItemCaseSensitive(json, "param");

    size_t param_size = strlen(obj->valuestring);
    pairing_init_set_buf(*pairing, obj->valuestring, param_size);
    // g
    obj = cJSON_GetObjectItemCaseSensitive(json, "g");
    element_init_G1(*g, *pairing);
    element_from_bytes(*g, obj->valuestring);
    // g_values
    for (int i = 0; i < 2 * (*n); i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "g%d", i);
        obj = cJSON_GetObjectItemCaseSensitive(json, key);
        element_init_G1(g_values[i], *pairing);
        element_from_bytes(g_values[i], obj->valuestring);
    }
    // mpk
    obj = cJSON_GetObjectItemCaseSensitive(json, "mpk");
    element_init_G1(*mpk, *pairing);
    element_from_bytes(*mpk, obj->valuestring);
    // dynK
    obj = cJSON_GetObjectItemCaseSensitive(json, "dynK");
    element_init_G1(*dynK, *pairing);
    element_from_bytes(*dynK, obj->valuestring);
    cJSON_Delete(json);
}

//  User Specific
void save_user_params(char *filename,
                      pbc_param_t pairing, element_t pub_u, element_t pub[])
{

    cJSON *json = cJSON_CreateObject();

    // pub_u
    char *value = element_to_bytes_array(pub_u);
    cJSON_AddStringToObject(json, "pub_u", value);
    // pub_values
    for (int i = 0; i < 5; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "pub%d", i);
        value = element_to_bytes_array(pub[i]);
        cJSON_AddStringToObject(json, key, value);
    }

    char *json_string = cJSON_Print(json);
    write_file(filename, json_string);

    free(value);
    cJSON_free(json_string);
    cJSON_Delete(json);
}


void load_user_params(char *filename,
                      pairing_t pairing,
                      element_t *pub_u, element_t pub[])
{
    char *json_data = read_file(filename);
    cJSON *json = cJSON_Parse(json_data);
    free(json_data);

    // g
    cJSON *obj = cJSON_GetObjectItemCaseSensitive(json, "pub_u");
    element_init_G1(*pub_u, pairing);
    element_from_bytes(*pub_u, obj->valuestring);

    // pub_values
    for (int i = 0; i < 5; i++)
    {

        char key[16];
        snprintf(key, sizeof(key), "pub%d", i);
        obj = cJSON_GetObjectItemCaseSensitive(json, key);

        if (i == 3)
            element_init_GT(pub[i], pairing);
        else
            element_init_G1(pub[i], pairing);

        element_from_bytes(pub[i], obj->valuestring);
    }

    cJSON_Delete(json);
}

void store_aggkey(char *filename, element_t k_u)
{

    cJSON *json = cJSON_CreateObject();
    // k_u
    char *value = element_to_bytes_array(k_u);
    cJSON_AddStringToObject(json, "k_u", value);

    char *json_string = cJSON_Print(json);
    write_file(filename, json_string);

    free(value);
    cJSON_free(json_string);
    cJSON_Delete(json);
}

void load_aggkey(char *filename, element_t *k_u, pairing_t pairing)
{   char *json_data = read_file(filename);
    cJSON *json = cJSON_Parse(json_data);
    free(json_data);

    cJSON *obj = cJSON_GetObjectItemCaseSensitive(json, "k_u");
    element_init_G1(*k_u, pairing);
    element_from_bytes(*k_u, obj->valuestring);
    cJSON_Delete(json);
}
