#include "../common/crypto.h"

#include <sqlite3.h>
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
extern int encrypt_file(const char *input_file, 
                        const char *output_file, 
                        unsigned char *key);

int register_with_cloud_server(const char *owner_name) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Send registration request
    send(sock, owner_name, strlen(owner_name), 0);
    close(sock);

    return 0;
}

int upload_file(const char *filename, 
                unsigned char *encryption_key) {
    // Encrypt file
    char encrypted_filename[MAX_FILENAME];
    snprintf(encrypted_filename, sizeof(encrypted_filename), 
             "%s.encrypted", filename);
    
    encrypt_file(filename, encrypted_filename, encryption_key);

    // Connect to cloud server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Send file metadata and encrypted file
    send(sock, encrypted_filename, strlen(encrypted_filename), 0);
    close(sock);

    return 0;
}

int generate_access_token(const char *filename, 
                          char *access_token) {
    // Generate unique access token
    // In real implementation, use cryptographically secure method
    snprintf(access_token, 64, "TOKEN_%s", filename);
    return 0;
}

int grant_user_access(const char *filename, 
                      const char *user_id) {
    char access_token[64];
    generate_access_token(filename, access_token);

    // Connect to cloud server to register access
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Send access grant information
    char message[256];
    snprintf(message, sizeof(message), 
             "GRANT:%s:%s:%s", filename, user_id, access_token);
    send(sock, message, strlen(message), 0);
    
    close(sock);
    return 0;
}

int main() {
    // Example workflow
    register_with_cloud_server("MyCompany");
    
    unsigned char encryption_key[32];  // 256-bit key
    // Initialize encryption key (secure method needed)
    upload_file("sensitive_document.txt", encryption_key);
    
    grant_user_access("sensitive_document.txt", "user123");

    return 0;
}