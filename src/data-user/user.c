#include "../common/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define MAX_FILENAME 256

// Crypto functions (from your existing implementation)
extern int decrypt_file(const char *input_file, 
                        const char *output_file, 
                        unsigned char *key);

int request_file_access(const char *filename, 
                        const char *user_id) {
    // Connect to cloud server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Send access request
    char request[256];
    snprintf(request, sizeof(request), 
             "ACCESS_REQUEST:%s:%s", filename, user_id);
    send(sock, request, strlen(request), 0);

    // Receive access token or denial
    char response[256];
    recv(sock, response, sizeof(response), 0);
    close(sock);

    return strncmp(response, "GRANTED", 7) == 0;
}

int download_file(const char *filename, 
                  unsigned char *decryption_key) {
    // Connect to cloud server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Request file download
    send(sock, filename, strlen(filename), 0);

    // Receive encrypted file
    char encrypted_filename[MAX_FILENAME];
    recv(sock, encrypted_filename, sizeof(encrypted_filename), 0);
    close(sock);

    // Decrypt file
    char decrypted_filename[MAX_FILENAME];
    snprintf(decrypted_filename, sizeof(decrypted_filename), 
             "%s.decrypted", filename);
    
    decrypt_file(encrypted_filename, 
                 decrypted_filename, 
                 decryption_key);

    return 0;
}

int main() {
    // Example workflow
    const char *user_id = "user123";
    const char *filename = "sensitive_document.txt";

    if (request_file_access(filename, user_id)) {
        unsigned char decryption_key[32];  // 256-bit key
        // Securely obtain decryption key (method needed)
        download_file(filename, decryption_key);
    }

    return 0;
}