#include "../common/crypto.h"
#include "../common/fileutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define DIRECT_COMM_PORT 5001

// Helper function to send a message to server

ssize_t receive_message(int socket, char *buffer, size_t size)
{
    memset(buffer, 0, size);

    // printf("\nwaiting for server.. \n");
    usleep(10000);

    ssize_t bytes_received = recv(socket, buffer, size - 1, 0);

    printf("\n%s\n", buffer);
    return bytes_received;
}

// Helper function to safely send messages
ssize_t send_message(int socket, const char *message)
{
    // printf("\nsending server.. %s\n", message);
    usleep(10000);

    return send(socket, message, strlen(message), 0);
}

//  direct interaction with owner
int setup_direct_communication(char *ownername, char *username)
{
    int direct_sock;
    struct sockaddr_in serv_addr;

    // Create socket
    if ((direct_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Direct communication socket creation error");
        return -1;
    }

    // printf("\nDirect Communication socket created\n");
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(DIRECT_COMM_PORT);

    // Convert IPv4 addresses from text to binary
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
    {
        perror("Invalid direct communication address");
        return -1;
    }

    char buffer[MAX_USERNAME];
    // Connect to owner's direct communication socket
    int refresh = 1;
    do
    {

        while (refresh && connect(direct_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {

            printf("\nWaiting for connection...\n");
            sleep(5);
            printf("1: Refresh, 0: Exit");

            scanf("%d", &refresh);
        }

        send(direct_sock, username, strlen(username), 0);
        memset(buffer, 0, MAX_USERNAME);
        recv(direct_sock, buffer, sizeof(buffer), 0);
        if (strcmp(buffer, ownername) == 0)
        {
            send(direct_sock, "1", 1, 0);
            break;
        }
        else
            send(direct_sock, "0", 1, 0);

    } while (refresh);
    if (!refresh)
        return -1;
    printf("\nConnected to owner's direct communication channel\n");
    return direct_sock;
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

// void receive_private_file(int socket, const char *filepath, int n, int data_classes,
//                           int data_class,
//                           element_t k_u,
//                           element_t pub[],
//                           int auth[],
//                           element_t g_values[],
//                           pairing_t pairing)
// {
//     // Receive file size from the server
//     char size_str[32];
//     receive_message(socket, size_str, sizeof(size_str));
//     long size = atol(size_str);
//     if (size == 0)
//     {
//         printf("File not found on server\n");
//         return;
//     }

//     // Send ready signal to the server
//     send_message(socket, "Ready");

//     // Open file to save received content
//     FILE *file = fopen(filepath, "wb");
//     if (!file)
//     {
//         printf("Error creating file: %s\n", filepath);
//         return;
//     }

//     // Allocate memory for receiving the data
//     char *data = malloc(size);
//     if (!data)
//     {
//         printf("Memory allocation failed\n");
//         fclose(file);
//         return;
//     }

//     int total = 0, received;
//     // Receive the file content in chunks
//     while (total < size)
//     {
//         usleep(10000);  // Sleep for a short time to avoid blocking too much

//         received = recv(socket, data + total, size - total, 0);
//         if (received <= 0)
//         {
//             printf("Error receiving data, received: %d\n", received);
//             break;
//         }
//         total += received;
//     }

//     // Decrypt the received data (assuming `dec` is your decryption function)
//     // Here, `data` contains the raw received data, which should be decrypted before being saved.
//     unsigned char *decrypted_data = dec(n, data_classes,
//                                         data_class,
//                                         k_u,
//                                         pub,
//                                         auth,
//                                         g_values,
//                                         pairing,
//                                         data);

//     // Check if decryption succeeded
//     if (!decrypted_data)
//     {
//         printf("Decryption failed\n");
//         free(data);
//         fclose(file);
//         return;
//     }

//     // Write the decrypted data to the file
//     fwrite(decrypted_data, 1, total, file);

//     // Free allocated memory
//     free(data);
//     free(decrypted_data);  // Assuming `dec` allocates new memory
//     fclose(file);

//     printf("File saved successfully to: %s\n", filepath);
// }

int main()
{

    int sock = 0, direct_sock;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    char input[BUFFER_SIZE];
    char username[MAX_USERNAME];
    char ownername[MAX_USERNAME];
    memset(buffer, 0, sizeof(buffer));
    memset(input, 0, sizeof(input));
    memset(username, 0, sizeof(username));

    int lambda, data_classes, n; // REUSAE
    pbc_param_t param;
    pairing_t pairing;
    mpz_t p;
    element_t g, g_values[n * 2];

    element_t msk[2], mpk, dynK;
    element_t k_u, pub_u, pub[5];
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

    // Choose interface (2 for user)
    receive_message(sock, buffer, sizeof(buffer));
    send_message(sock, "2");

    // Get sign in/create new prompt
    receive_message(sock, buffer, sizeof(buffer));

    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    send_message(sock, input);

    if (input[0] == '1')
    { // Sign in
        // Handle username/password
        receive_message(sock, buffer, sizeof(buffer));
        fgets(username, sizeof(username), stdin);
        username[strcspn(username, "\n")] = 0;
        send_message(sock, username);

        receive_message(sock, buffer, sizeof(buffer));
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        // Check if need second password attempt
        receive_message(sock, buffer, sizeof(buffer));
        if (strstr(buffer, "Incorrect password") != NULL)
        {
            receive_message(sock, buffer, sizeof(buffer));

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
        fgets(username, sizeof(username), stdin);
        username[strcspn(username, "\n")] = 0;
        send_message(sock, username);

        receive_message(sock, buffer, sizeof(buffer));
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        receive_message(sock, buffer, sizeof(buffer));
        if (strstr(buffer, "Error") != NULL)
        {
            close(sock);
            return 0;
        }
    }

    while (1)
    {
        // Get operation choice from server
        receive_message(sock, buffer, sizeof(buffer));

        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        if (input[0] == '3')
            break;

        switch (input[0])
        {
        case '1':
        {
            // owner name prompt
            receive_message(sock, buffer, sizeof(buffer));
            fgets(ownername, sizeof(ownername), stdin);
            ownername[strcspn(ownername, "\n")] = 0;
            send_message(sock, ownername);

            // get param file
            const char *base_path = "./params/";
            size_t path_len = strlen(base_path) + strlen(ownername) + strlen("/aggkey.param") + 1;
            char *file_path_public = (char *)malloc(path_len);
            snprintf(file_path_public, path_len, "%s%s/aggkey.param", base_path, ownername);

            receive_file(sock,file_path_public ); // receive the params file
            load_public_params(file_path_public,&lambda,&data_classes,&n,&pairing,&g,g_values,&mpk,&dynK);
            
            receive_message(sock, buffer, sizeof(buffer)); // Auth_u prompt
            receive_message(sock, buffer, sizeof(buffer));     // AUth_u valoe

            // Calcualte Auth-u
            int *auth_u = (int *)calloc(data_classes, sizeof(int));
            char *auth_str = strdup(buffer);
            char *token = strtok(auth_str, ",");
            while (token != NULL)
            {
                if (strlen(token) > 0)
                {
                    int num = atoi(token);
                    if (num >= 0 && num <= n - 1)
                    {
                        auth_u[num] = 1;
                    }
                }
                token = strtok(NULL, ",");
            }
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
        case '2':
        {

            // owner name prompt
            receive_message(sock, buffer, sizeof(buffer));

            // Get user input
            fgets(ownername, sizeof(ownername), stdin);
            ownername[strcspn(ownername, "\n")] = 0;
            send_message(sock, ownername);

            // get param file
            const char *base_path = "./params/";
            size_t path_len = strlen(base_path) + strlen(ownername) + strlen("/aggkey.param") + 1;
            char *file_path_public = (char *)malloc(path_len);
            snprintf(file_path_public, path_len, "%s%s/aggkey.param", base_path, ownername);

            receive_file(sock,file_path_public ); // receive the params file
            load_public_params(file_path_public,&lambda,&data_classes,&n,&pairing,&g,g_values,&mpk,&dynK);

            direct_sock = setup_direct_communication(ownername, username);
            if (direct_sock < 0)
            {
                printf("Failed to establish direct communication\n");
            }
            else
            {
                const char *base_path = "./params/";
                size_t path_len = strlen(base_path) + strlen(ownername) + strlen("/aggkey.param") + 1;
                char *file_path = (char *)malloc(path_len);
                snprintf(file_path, path_len, "%s%s/aggkey.param", base_path, ownername);
                receive_file(direct_sock, file_path);
                close(direct_sock);
            }

            send_message(sock, "Direct Communication Over");
            close(sock);
            exit(1);
        }
        case '3':
        {
            break;
        }
        }

        fflush(stdin);
    }

    close(sock);
    return 0;
}