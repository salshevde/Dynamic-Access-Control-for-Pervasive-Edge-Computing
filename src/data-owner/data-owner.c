#include "../common/crypto.h"

#define MAX_USERS 100

//  Mutex for thread-safe
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
// void encrypt_file()
// int main(int argc, char argv[])
// {

//     int lambda = 1024, data_classes = 4;
//     int n = data_classes * 2;
//     pbc_param_t param;
//     pairing_t pairing;
//     mpz_t p;
//     element_t g, g_values[n * 2];

//     element_t msk[2], mpk, dynK;
//     element_t k_u, pub_u, pub[5];

//     //  Cryptosystem initialization
//     initialize(
//         lambda,
//         n, data_classes,
//         param,
//         &pairing,
//         &g,
//         g_values);

//     gen(pairing,
//         g,
//         msk,
//         &mpk,
//         &dynK);

//     // Take auth_u input
//     // int auth_u

//     extract(pairing,
//         msk,
//         mpk,
//         dynK,
//         g,
//         auth_u,
//         g_values,
//         n, data_classes,
//         &k_u,
//         &pub_u, pub);

//     return 0;
// }

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 5000
#define BUFFER_SIZE 1024
#define MAX_FILENAME 256
#define MAX_USERNAME 64
#define MAX_PASSWORD 64
#define SERVER_IP "127.0.0.1"
// Parameter Handling: NOT COMPLETE
void save_params(int lambda, int data_classes, element_t g, element_t k_u, element_t g_values[], element_t msk[2], element_t mpk, element_t dynK, element_t pub_u, element_t pub[])
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

// void load_public_params(const char *filename, pairing_t *pairing, element_t *g, element_t *g_values, int n) {
//     FILE *fptr = fopen(filename, "rb");
//     if (!fptr) {
//         perror("Failed to open file for reading");
//         exit(1);
//     }

//     // Load the pairing from the file
//     char param_buffer[2048]; // Adjust size as necessary
//     size_t count = fread(param_buffer, 1, sizeof(param_buffer), fptr);
//     if (count == 0) {
//         perror("Failed to read parameter data");
//         fclose(fptr);
//         exit(1);
//     }
//     pairing_init_set_buf(*pairing, param_buffer, count);

//     // Load g from the file
//     element_init_G1(*g, *pairing);
//     element_from_bytes_compressed(*g, param_buffer); // Adjust buffer handling based on format

//     // Load g_values from the file
//     for (int i = 0; i < 2 * n; i++) {
//         element_init_G1(g_values[i], *pairing);
//         element_from_bytes_compressed(g_values[i], param_buffer); // Adjust buffer handling
//     }

//     fclose(fptr);
// }

// void load_private_params(const char *filename, pairing_t *pairing, element_t *g, element_t *g_values, int n) {
//     FILE *fptr = fopen(filename, "rb");
//     if (!fptr) {
//         perror("Failed to open file for reading");
//         exit(1);
//     }

//     // Load the pairing from the file
//     char param_buffer[2048]; // Adjust size as necessary
//     size_t count = fread(param_buffer, 1, sizeof(param_buffer), fptr);
//     if (count == 0) {
//         perror("Failed to read parameter data");
//         fclose(fptr);
//         exit(1);
//     }
//     pairing_init_set_buf(*pairing, param_buffer, count);

//     // Load g from the file
//     element_init_G1(*g, *pairing);
//     element_from_bytes_compressed(*g, param_buffer); // Adjust buffer handling based on format

//     // Load g_values from the file
//     for (int i = 0; i < 2 * n; i++) {
//         element_init_G1(g_values[i], *pairing);
//         element_from_bytes_compressed(g_values[i], param_buffer); // Adjust buffer handling
//     }

//     fclose(fptr);
// }

//
// Helper function to send a message to server
void send_message(int socket, const char *message)
{
    send(socket, message, strlen(message), 0);
}

int check_socket_status(int socket)
{
    int error = 0;
    socklen_t len = sizeof(error);
    int retval = getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &len);

    if (retval != 0)
    {
        printf("Error getting socket error status\n");
        return -1;
    }

    if (error != 0)
    {
        printf("Socket error: %s\n", strerror(error));
        return -1;
    }

    return 0;
}
// Helper function to receive a message from server
void receive_message(int socket, char *buffer, int size)
{
    memset(buffer, 0, size);
    recv(socket, buffer, size - 1, 0);
    printf("%s", buffer);
}

// Function to send a file to server
void send_file(int socket, const char *filepath)
{
    FILE *file = fopen(filepath, "rb");
    if (!file)
    {
        printf("Error opening file: %s\n", filepath);
        send_message(socket, "0");
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Send size
    char size_str[32];
    sprintf(size_str, "%ld", size);
    send_message(socket, size_str);

    // Wait for server ready signal
    char buffer[BUFFER_SIZE];
    receive_message(socket, buffer, sizeof(buffer));

    // Send file content
    char *data = malloc(size);
    fread(data, 1, size, file);
    int total = 0, sent;
    while (total < size)
    {
        sent = send(socket, data + total, size - total, 0);
        if (sent <= 0)
            break;
        total += sent;
    }

    free(data);
    fclose(file);
}

// Function to receive a file from server
void receive_file(int socket, const char *filepath)
{
    char size_str[32];
    receive_message(socket, size_str, sizeof(size_str));

    long size = atol(size_str);
    if (size == 0)
    {
        printf("File not found on server\n");
        return;
    }

    // Send ready signal
    send_message(socket, "Ready");

    // Receive and save file
    FILE *file = fopen(filepath, "wb");
    if (!file)
    {
        printf("Error creating file: %s\n", filepath);
        return;
    }

    char *data = malloc(size);
    int total = 0, received;
    while (total < size)
    {
        received = recv(socket, data + total, size - total, 0);
        if (received <= 0)
            break;
        total += received;
    }

    fwrite(data, 1, total, file);
    free(data);
    fclose(file);

    printf("File saved successfully to: %s\n", filepath);
}

// Function to handle owner operations
void handle_owner_operations(int sock)
{
    char buffer[BUFFER_SIZE];
    char input[BUFFER_SIZE];

    while (1)
    {
        // Get operation choice from server
        receive_message(sock, buffer, sizeof(buffer));

        // Get user input
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        if (input[0] == '6')
        { // Exit
            break;
        }

        switch (input[0])
        {
        case '1':
        { // Upload
            // Get filename prompt
            receive_message(sock, buffer, sizeof(buffer));

            // Send filename
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);
            // Get data class prompt

            receive_message(sock, buffer, sizeof(buffer));

            // Send Data Class
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);

            // Get local file path
            printf("Enter local file path: ");
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;

            // Send file
            send_file(sock, input);

            // Get upload result
            receive_message(sock, buffer, sizeof(buffer));
            break;
        }
        case '2':
        { // Delete
            // Get filename prompt
            receive_message(sock, buffer, sizeof(buffer));

            // Send filename
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);

            // Get delete result
            receive_message(sock, buffer, sizeof(buffer));
            break;
        }
        case '3':
        { // Update params
            printf("Enter params file path: ");
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;

            send_file(sock, input);

            // Get update result
            receive_message(sock, buffer, sizeof(buffer));
            break;
        }
        case '4':
        { // UpdateSet
            // printf("Enter params file path: ");
            // fgets(input, sizeof(input), stdin);
            // input[strcspn(input, "\n")] = 0;

            // send_file(sock, input);

            receive_message(sock, buffer, sizeof(buffer));
            // Send username
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);

            receive_message(sock, buffer, sizeof(buffer));
            // Send username
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);

            // Get update result
            receive_message(sock, buffer, sizeof(buffer));

            break;
        }
        case '5':
        { // Receive my file
            // Get filename prompt
            receive_message(sock, buffer, sizeof(buffer));
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);

            // Get save location
            printf("Enter where to save the file: ");
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;

            // Receive the file
            receive_file(sock, input);
            break;
        }
        }
    }
}

// threaded UPDATE PLS
void *thread_handle(void *arg)
{
    client_args *args = (client_args *)arg;

    // Detach the thread so its resources are automatically released
    pthread_detach(pthread_self());

    // Call the original handle_client function
    handle_client(args->db, args->client_socket);

    // Cleanup
    close(args->client_socket);
    free(args);

    return NULL;
}

int main()
{
    // CRYPTOSYSTEM
    int lambda = 1024, data_classes; // REUSAE
    int n = data_classes * 2;        // REUSAE
    pbc_param_t param;
    pairing_t pairing;
    mpz_t p;
    element_t g, g_values[n * 2];

    element_t msk[2], mpk, dynK;
    element_t k_u, pub_u, pub[5];

    // NETWORK
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    char input[BUFFER_SIZE];

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Choose interface (1 for owner)
    receive_message(sock, buffer, sizeof(buffer));
    send_message(sock, "1");

    // Get sign in/create new prompt
    receive_message(sock, buffer, sizeof(buffer));
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    send_message(sock, input);

    if (input[0] == '1')
    { // Sign in
        // Handle username/password
        receive_message(sock, buffer, sizeof(buffer));
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        receive_message(sock, buffer, sizeof(buffer));
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        // Check if need second password attempt
        receive_message(sock, buffer, sizeof(buffer));
        if (strstr(buffer, "Incorrect password") != NULL)
        {
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);

            receive_message(sock, buffer, sizeof(buffer));
            if (strstr(buffer, "Authentication failed") != NULL)
            {
                close(sock);
                return 0;
            }
        }
    }
    else if (input[0] == '2')
    { // Create new account
        // Handle new account creation
        receive_message(sock, buffer, sizeof(buffer));
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        receive_message(sock, buffer, sizeof(buffer));
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        receive_message(sock, buffer, sizeof(buffer));
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        receive_message(sock, buffer, sizeof(buffer));
        printf("Enter params file path: ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_file(sock, input);

        receive_message(sock, buffer, sizeof(buffer));
        if (strstr(buffer, "Error") != NULL)
        {
            close(sock);
            return 0;
        }

        //  Cryptosystem initialization
        initialize(
            lambda,
            n, data_classes,
            param,
            &pairing,
            &g,
            g_values);

        gen(pairing,
            g,
            msk,
            &mpk,
            &dynK);
    }

    // Handle owner operations
    handle_owner_operations(sock);

    close(sock);
    return 0;
}