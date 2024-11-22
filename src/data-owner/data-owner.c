#include "../common/crypto.h"
#include "../common/fileutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 5000
#define MAX_USERS 100
#define DIRECT_COMM_PORT 5001 // Different from main server port
#define BUFFER_SIZE 1024
#define MAX_USERNAME 64
#define MAX_PASSWORD 64
#define SERVER_IP "127.0.0.1"

//  Mutex for thread-safe
pthread_mutex_t requests_mutex = PTHREAD_MUTEX_INITIALIZER;

//  Direct communication with user
typedef struct
{
    char username[64];
    int socket;
    int is_active;
} UserConnection;
UserConnection connection_requests[MAX_USERS];
int request_count = 0;

typedef struct
{
    int server_fd;
    char *ownername;
} owner_args;

// Function to create a direct communication socket
void add_connection_request(const char *username, int client_socket)
{
    pthread_mutex_lock(&requests_mutex);

    // Check if list is full
    if (request_count >= MAX_USERS)
    {
        printf("Connection request list is full\n");
        pthread_mutex_unlock(&requests_mutex);
        return;
    }

    // Add new request
    strncpy(connection_requests[request_count].username, username, 63);
    connection_requests[request_count].socket = client_socket;
    connection_requests[request_count].is_active = 1;
    request_count++;

    pthread_mutex_unlock(&requests_mutex);
}

int choose_connection_request()
{
    int choice;

    // Display available connection requests
    printf("Available Connection Requests:\n");
    for (int i = 0; i < request_count; i++)
    {
        if (connection_requests[i].is_active)
        {
            printf("%d. %s\n", i + 1, connection_requests[i].username);
        }
    }

    // Get user choice
    printf("Enter the number of the user to connect (0 to refresh, -1 to exit): ");
    scanf("%d", &choice);

    if (choice < -1 || choice > request_count || (choice > 0 && !connection_requests[choice - 1].is_active))
    {
        printf("Invalid selection\n");
        return -3;
    }

    if (choice == 0)
    {
        return -2;
    }
    if (choice == -1)
    {
        return -1;
    }

    choice--;
    // Return socket of selected user
    return choice;
}

int setup_direct_communication_listener()
{
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Direct communication server socket creation failed");
        return -1;
    }

    // Allow socket to reuse address
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt)))
    {
        perror("Direct communication setsockopt failed");
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(DIRECT_COMM_PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Direct communication bind failed");
        return -1;
    }

    // Listen for connections
    if (listen(server_fd, MAX_USERS) < 0)
    {
        perror("Direct communication listen failed");
        return -1;
    }

    printf("Waiting for direct communication requests...\n");
    return server_fd;
}

void *handle_connection_requests(void *arg)
{
    owner_args *args = (owner_args *)arg;

    int server_fd = args->server_fd;
    char *ownername = args->ownername;
    struct sockaddr_in client_address;
    socklen_t client_addrlen = sizeof(client_address);

    while (1)
    {
        printf("running");
        // Accept incoming connection
        int client_socket = accept(server_fd,
                                   (struct sockaddr *)&client_address,
                                   &client_addrlen);
        if (client_socket < 0)
        {
            perror("Connection accept failed");
            continue;
        }

        // Get username (you might want to implement a more robust method)
        char username[64];
        memset(username, 0, sizeof(username));
        char cmp[2] = {0};
        ssize_t bytes_received = recv(client_socket, username, sizeof(username) - 1, 0);

        printf("Found user %s", username);
        if (bytes_received < 0)
        {
            perror("Error receiving username");
            close(client_socket);
            continue;
        }

        printf("sending name %s", ownername);

        send(client_socket, ownername, strlen(ownername), 0);

        recv(client_socket, cmp, sizeof(cmp) - 1, 0);

        if (strcmp(cmp, "1") == 0)
        {
            printf("User added");

            // Add to connection requests
            add_connection_request(username, client_socket);
        }
        else
        {
            printf("User not right");

            close(client_socket);
        }
    }
}
// ENCRYPTION
// Parameter Handling: NOT COMPLETE

// Helper function to receive a message from server

ssize_t receive_message(int socket, char *buffer, size_t size)
{
    memset(buffer, 0, size);

    printf("\nwaiting for server.. \n");
    usleep(10000);
    ssize_t bytes_received = recv(socket, buffer, size - 1, 0);

    printf("\n%s\n", buffer);
    return bytes_received;
}

// Helper function to safely send messages
ssize_t send_message(int socket, const char *message)
{
    printf("\nsending server.. \n");
    usleep(10000);

    return send(socket, message, strlen(message), 0);
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

// Function to send a file to server
void send_public_file(int socket, const char *filepath)
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
        usleep(10000);

        sent = send(socket, data + total, size - total, 0);
        if (sent <= 0)
            break;
        total += sent;
    }

    free(data);
    fclose(file);
}
void send_private_file(int socket, const char *filepath, int data_class,
                       int n, int data_classes,
                       element_t mpk,
                       element_t g,
                       element_t g_values[],
                       pairing_t pairing,
                       element_t dynK)
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
    unsigned char *pt_buffer = (unsigned char *)malloc(size);
    fread(pt_buffer, 1, size, file);
    const SerializedCiphertext *ciphertext = enc(data_class, n, data_classes, mpk, g, g_values, pairing, dynK, pt_buffer);

    // Send size
    char size_str[32];
    sprintf(size_str, "%ld", ciphertext->total_length);
    send_message(socket, size_str);

    // Wait for server ready signal
    char buffer[BUFFER_SIZE];
    receive_message(socket, buffer, sizeof(buffer));
    printf("%ld", ciphertext->total_length);

    // Send file content
    int total = 0, sent;
    while (total < ciphertext->total_length)
    {
        sent = send(socket, ciphertext->buffer + total, ciphertext->total_length - total, 0);
        if (sent <= 0)
            break;
        total += sent;
    }

    printf("here");
    free(pt_buffer);
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
        usleep(10000);

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
void handle_owner_operations(int sock, char *ownername,
                             int n, int data_classes,
                             element_t msk[],
                             element_t mpk,
                             element_t g,
                             element_t g_values[],
                             pairing_t pairing,
                             pbc_param_t param,
                             element_t dynK)
{
    char buffer[BUFFER_SIZE];
    char input[BUFFER_SIZE];
    char username[MAX_USERNAME];
    char data_class_str[16];
    int data_class;
    int server_fd;
    pthread_t request_thread;

    element_t pub_u, pub[5], k_u;
    while (1)
    {
        // Get operation choice from server
        receive_message(sock, buffer, sizeof(buffer));

        // Get user input
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        send_message(sock, input);

        if (input[0] == '7')
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
            fgets(data_class_str, sizeof(data_class_str), stdin);
            data_class_str[strcspn(data_class_str, "\n")] = 0;
            send_message(sock, data_class_str);
            data_class = atoi(data_class_str);
            // Get local file path
            printf("Enter local file path: ");
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;

            // Send file
            // send_public_file(sock,input);
            send_private_file(sock, input, data_class, n, data_classes, mpk, g, g_values, pairing, dynK);

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

            send_public_file(sock, input);

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
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;
            send_message(sock, username);

            receive_message(sock, buffer, sizeof(buffer));
            // REvoke /ADD?
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;
            send_message(sock, input);
            int data_class = 0;

            char *token = strtok(strdup(input), " ");

            if (token != NULL)
            {
                strcpy(buffer, token);
                token = strtok(NULL, " ");
                if (token != NULL)
                {
                    data_class = atoi(token);
                }
            }

            int action = -1;

            if (strcmp(buffer, "add") == 0)
            {
                action = 1;
            }
            else if (strcmp(buffer, "revoke") == 0)
            {
                action = 0;
            }
            // Get Auth_u
            receive_message(sock, buffer, sizeof(buffer)); // Auth-u prompt
            receive_message(sock, buffer, sizeof(buffer)); // Auth-u value

            // Calcualte Auth-u
            int *auth_u = (int *)calloc(data_classes, sizeof(int));
            char *auth_str = strdup(buffer);
            token = strtok(auth_str, ",");
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
            // Get update result : IF NEW -> transmit K_u
            receive_message(sock, buffer, sizeof(buffer));
            // check if invalid
            if (strstr(buffer, "Invalid") != NULL)
            {
                break;
            }
            else if (strstr(buffer, "UPDATING") != NULL)
            {
                //
                const char *base_path = "./params/";
                size_t path_len = strlen(base_path) + strlen(username) + strlen("/user.param") + 1;
                char *user_param = (char *)malloc(path_len);
                
                snprintf(user_param, path_len, "%s%s/user.param", base_path, username);

                load_user_params(user_param, pairing, &pub_u, pub);
                updateSet(data_class, n, data_classes, auth_u, action, &dynK, msk, pub_u, pub, mpk, g, g_values, pairing);
                receive_message(sock, buffer, sizeof(buffer));
            }
            else if (strncmp("NEW USER", buffer, 8) == 0)
            {
                //
                char *user_param;
                extract(pairing, msk, mpk, dynK, g, auth_u, g_values, n, data_classes, &k_u, &pub_u, pub);
                save_user_params(user_param, param, pub_u, pub);
                // Setup direct communication listener
                server_fd = setup_direct_communication_listener();
                if (server_fd < 0)
                {
                    break;
                }
                owner_args arg;
                arg.ownername = ownername;
                arg.server_fd = server_fd;
                if (pthread_create(&request_thread, NULL, handle_connection_requests, &arg) != 0)
                {
                    perror("Failed to create request handling thread");
                    break;
                }
                int selected_socket;
                do
                {
                    selected_socket = choose_connection_request();
                    if (selected_socket == -1)
                    {
                        printf("\nUser Not online!!\n");
                        break;
                    }
                    if (selected_socket >= 0)
                    {
                        UserConnection user = connection_requests[selected_socket];

                        const char *base_path = "./params/";
                        size_t path_len = strlen(base_path) + strlen(user.username) + strlen("/aggkey.param") + 1;
                        char *file_path = (char *)malloc(path_len);
                        snprintf(file_path, path_len, "%s%s/aggkey.param", base_path, user.username);
                        store_aggkey(file_path, k_u);
                        printf("\nConnected to %s\n", user.username);
                        send_public_file(user.socket, file_path);
                        close(user.socket);
                    }
                } while (selected_socket == -2);

                printf("Ending direct communication...");
                send_message(sock, "Direct Communication Over!");
            }
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
        case '6':
        {
            // Setup direct communication listener
            server_fd = setup_direct_communication_listener();
            if (server_fd < 0)
            {
                break;
            }

            if (pthread_create(&request_thread, NULL, handle_connection_requests, &server_fd) != 0)
            {
                perror("Failed to create request handling thread");
                break;
            }

            while (1)
            {
                int selected_socket = choose_connection_request();
                printf("%d", selected_socket);
                if (selected_socket == -1)
                {
                    printf("Ending direct communication...");
                    send_message(sock, "Direct Communication Over!");
                    break;
                }
                if (selected_socket == -2)
                    continue;

                if (selected_socket >= 0)
                {

                    // Perform communication with selected user
                    send_message(selected_socket, ownername);
                    receive_message(selected_socket, buffer, sizeof(buffer)); // while it

                    close(selected_socket);
                }
            }
            printf("Ending direct communication...");
            send_message(sock, "Direct Communication Over!");
            pthread_join(request_thread, NULL);

            break;
        }
        }
    }
}

int main()
{
    // CRYPTOSYSTEM
    int lambda = 1024, data_classes = 5; // setting values
    int n = data_classes * 2;            // REUSAE
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
    char ownername[MAX_USERNAME];
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
        fgets(ownername, sizeof(ownername), stdin);
        ownername[strcspn(ownername, "\n")] = 0;
        send_message(sock, ownername);

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
        // Load existing cryptosystem
        load_public_params("./params/public.param", &lambda, &data_classes, &n, &pairing, &g, g_values, &mpk, &dynK);
        load_private_params("./params/private.param", msk, pairing);
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
        send_public_file(sock, input);

        receive_message(sock, buffer, sizeof(buffer));
        if (strstr(buffer, "Error") != NULL)
        {
            close(sock);
            exit(1);
        }

        //  Cryptosystem initialization
        initialize(
            lambda,
            n, data_classes,
            &param,
            &pairing,
            &g,
            g_values);

        gen(pairing,
            g,
            msk,
            &mpk,
            &dynK);

        save_private_params("./params/private.param", msk);
        save_public_params("./params/public.param", lambda, data_classes, n, param, g, g_values, mpk, dynK);
    }

    // Handle owner operations
    handle_owner_operations(sock, ownername, n, data_classes, msk, mpk, g, g_values, pairing, param, dynK);

    close(sock);
    return 0;
}