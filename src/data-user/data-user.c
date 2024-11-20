#include "../common/crypto.h"
// data_user.c
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
#define SERVER_IP "127.0.0.1"

// Helper function to send a message to server
void send_message(int socket, const char *message)
{
    send(socket, message, strlen(message), 0);
}

// Helper function to receive a message from server
void receive_message(int socket, char *buffer, int size)
{
    memset(buffer, 0, size);
    recv(socket, buffer, size - 1, 0);
    printf("%s", buffer);
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

int main()
{
    
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
        if (strstr(buffer, "Error") != NULL)
        {
            close(sock);
            return 0;
        }
    }

    // Get owner username prompt
    receive_message(sock, buffer, sizeof(buffer));
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    send_message(sock, input);

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

    close(sock);
    return 0;
}