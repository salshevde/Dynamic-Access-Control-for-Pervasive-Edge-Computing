#include "../common/crypto.h"
// server.c
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
#define BUFFER_SIZE 1024
#define MAX_FILENAME 256
#define MAX_USERNAME 64
#define MAX_PASSWORD 64
#define MAX_CLIENTS 100

//  Mutex for thread-safe 
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    sqlite3* db;
    int client_socket;
} client_args;


// database functions
void init_database(sqlite3 **db)
{
    int rc = sqlite3_open("cloud_storage.db", db);
    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        return;
    }

    char *sql = "CREATE TABLE IF NOT EXISTS owners ("
                "username TEXT PRIMARY KEY,"
                "password TEXT,"
                "public_params BLOB"
                ");"
                "CREATE TABLE IF NOT EXISTS files ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "owner TEXT,"
                "filename TEXT,"
                "data BLOB,"
                "FOREIGN KEY (owner) REFERENCES owners(username)"
                ");";

    char *err_msg = 0;
    rc = sqlite3_exec(*db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
}

// Network helper functions

ssize_t receive_message(int socket, char *buffer, size_t size)
{
    memset(buffer, 0, size);
    ssize_t bytes_received = recv(socket, buffer, size - 1, 0);

    if (bytes_received > 0)
    {
        // Remove trailing newline if present
        if (buffer[bytes_received - 1] == '\n')
        {
            buffer[bytes_received - 1] = '\0';
        }
    }

    return bytes_received;
}

// Helper function to safely send messages
ssize_t send_message(int socket, const char *message)
{
    return send(socket, message, strlen(message), 0);
}
// Receive file data with size prefix
char *receive_file_data(int socket, int *size)
{
    char size_str[32];
    receive_message(socket, size_str, sizeof(size_str));
    *size = atoi(size_str);

    send_message(socket, "Ready");

    char *data = malloc(*size);
    int total = 0, received;
    while (total < *size)
    {
        received = recv(socket, data + total, *size - total, 0);
        if (received <= 0)
            break;
        total += received;
    }
    return data;
}

// Send file data with size prefix
void send_file_data(int socket, const char *data, int size)
{
    char size_str[32];
    sprintf(size_str, "%d", size);
    send_message(socket, size_str);

    char buffer[BUFFER_SIZE];
    receive_message(socket, buffer, sizeof(buffer)); // Wait for ready

    int total = 0, sent;
    while (total < size)
    {
        sent = send(socket, data + total, size - total, 0);
        if (sent <= 0)
            break;
        total += sent;
    }
}

// Handle owner authentication
int authenticate_owner(sqlite3 *db, int client_socket, char *username)
{
    char password[MAX_PASSWORD];
    int attempts = 2;

    send_message(client_socket, "Username: ");
    receive_message(client_socket, username, MAX_USERNAME);

    while (attempts > 0)
    {
        send_message(client_socket, "Password: ");
        receive_message(client_socket, password, MAX_PASSWORD);

        sqlite3_stmt *stmt;
        const char *sql = "SELECT password FROM owners WHERE username = ?";
        sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            const char *stored_pass = (const char *)sqlite3_column_text(stmt, 0);
            if (strcmp(password, stored_pass) == 0)
            {
                send_message(client_socket, "\nAuth Success \n");

                sqlite3_finalize(stmt);
                return 1;
            }
        }

        sqlite3_finalize(stmt);
        attempts--;

        if (attempts > 0)
        {
            send_message(client_socket, "Incorrect password. One more try: ");
        }
        else
        {
            send_message(client_socket, "Authentication failed. Disconnecting.\n");
        }
    }

    return 0;
}

// Handle owner operations
void handle_owner_operations(sqlite3 *db, int client_socket, const char *username)
{
    char buffer[BUFFER_SIZE];
    char filename[MAX_FILENAME];

    while (1)
    {
        printf("here");

        send_message(client_socket, "Choose operation (1: Upload, 2: Delete, 3: Update Params, 4: Exit): ");
        receive_message(client_socket, buffer, sizeof(buffer));

        if (buffer[0] == '1')
        { // Upload
            send_message(client_socket, "Filename: ");
            receive_message(client_socket, filename, sizeof(filename));

            int size;
            char *file_data = receive_file_data(client_socket, &size);

            sqlite3_stmt *stmt;
            const char *sql = "INSERT INTO files (owner, filename, data) VALUES (?, ?, ?)";
            sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 3, file_data, size, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE)
            {
                send_message(client_socket, "Error uploading file.\n");
            }
            else
            {
                send_message(client_socket, "File uploaded successfully.\n");
            }

            sqlite3_finalize(stmt);
            free(file_data);
        }
        else if (buffer[0] == '2')
        { // Delete
            send_message(client_socket, "Filename to delete: ");
            receive_message(client_socket, filename, sizeof(filename));

            sqlite3_stmt *stmt;
            const char *sql = "DELETE FROM files WHERE owner = ? AND filename = ?";
            sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);

            int result = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (result != SQLITE_DONE)
            {
                send_message(client_socket, "Error deleting file.\n");
            }
            else if (sqlite3_changes(db) > 0)
            {
                send_message(client_socket, "File deleted successfully.\n");
            }
            else
            {
                send_message(client_socket, "File not found.\n");
            }
            send_message(client_socket, "\n"); // DEBUG
        }
        else if (buffer[0] == '3')
        { // Update params
            int size;
            char *params_data = receive_file_data(client_socket, &size);

            sqlite3_stmt *stmt;
            const char *sql = "UPDATE owners SET public_params = ? WHERE username = ?";
            sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
            sqlite3_bind_blob(stmt, 1, params_data, size, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE)
            {
                send_message(client_socket, "Error updating params.\n");
            }
            else
            {
                send_message(client_socket, "Params updated successfully.\n");
            }

            sqlite3_finalize(stmt);
            free(params_data);
        }
        else if (buffer[0] == '4')
        { // Exit
            break;
        }
    }
}

// Handle user operations
void handle_user(sqlite3 *db, int client_socket)
{
    char owner[MAX_USERNAME];
    char filename[MAX_FILENAME];

    send_message(client_socket, "Enter owner username: ");
    receive_message(client_socket, owner, sizeof(owner));

    send_message(client_socket, "Enter filename: ");
    receive_message(client_socket, filename, sizeof(filename));

    sqlite3_stmt *stmt;
    const char *sql = "SELECT data FROM files WHERE owner = ? AND filename = ?";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const void *data = sqlite3_column_blob(stmt, 0);
        int size = sqlite3_column_bytes(stmt, 0);
        send_file_data(client_socket, data, size);
    }
    else
    {
        send_message(client_socket, "0");
    }

    sqlite3_finalize(stmt);
}

// Handle new owner registration
void handle_new_owner(sqlite3 *db, int client_socket)
{
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];

    send_message(client_socket, "New username: ");
    receive_message(client_socket, username, sizeof(username));

    send_message(client_socket, "New password: ");
    receive_message(client_socket, password, sizeof(password));

    send_message(client_socket, "Send public params file (size in bytes): ");
    int size;
    char *params_data = receive_file_data(client_socket, &size);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO owners (username, password, public_params) VALUES (?, ?, ?)";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, params_data, size, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        send_message(client_socket, "Error creating account.\n");
    }
    else
    {
        send_message(client_socket, "Account created successfully.\n");
    }

    sqlite3_finalize(stmt);
    free(params_data);
}

// Main client handler
void handle_client(sqlite3 *db, int client_socket)
{
    char buffer[BUFFER_SIZE];
    char username[MAX_USERNAME];

    // Debug print for entry
    // printf("DEBUG: Entered handle_client\n");

    // Clear buffers to prevent garbage data
    memset(buffer, 0, BUFFER_SIZE);
    memset(username, 0, MAX_USERNAME);

    // Interface selection
    if (send_message(client_socket, "Choose interface (1: Owner, 2: User): ") <= 0)
    {
        printf("ERROR: Failed to send interface selection message\n");
        return;
    }

    ssize_t bytes_received = receive_message(client_socket, buffer, sizeof(buffer));
    if (bytes_received <= 0)
    {
        printf("ERROR: Failed to receive interface selection\n");
        return;
    }

    // printf("DEBUG: Interface selection received: %c\n", buffer[0]);

    if (buffer[0] == '1')
    { // Owner
        // printf("DEBUG: Owner interface selected\n");

        if (send_message(client_socket, "1: Sign in, 2: Create new: ") <= 0)
        {
            printf("ERROR: Failed to send owner options\n");
            return;
        }

        bytes_received = receive_message(client_socket, buffer, sizeof(buffer));
        if (bytes_received <= 0)
        {
            printf("ERROR: Failed to receive owner option\n");
            return;
        }

        // printf("DEBUG: Owner option selected: %c\n", buffer[0]);

        if (buffer[0] == '1')
        { // Sign in
            // printf("DEBUG: Owner sign in selected\n");

            if (authenticate_owner(db, client_socket, username))
            {
                // printf("DEBUG: Owner authenticated successfully: %s\n", username);
                handle_owner_operations(db, client_socket, username);
            }
            else
            {
                printf("ERROR: Owner authentication failed\n");
            }
        }
        else if (buffer[0] == '2')
        { // Create new
            // printf("DEBUG: Owner creation selected\n");
            handle_new_owner(db, client_socket);
        }
        else
        {
            printf("ERROR: Invalid owner option selected: %c\n", buffer[0]);
        }
    }
    else if (buffer[0] == '2')
    { // User
        // printf("DEBUG: User interface selected\n");
        handle_user(db, client_socket);
    }
    else
    {
        printf("ERROR: Invalid interface selection: %c\n", buffer[0]);
    }
}

// threaded 
void* thread_handle_client(void* arg) {
    client_args* args = (client_args*)arg;
    
    // Detach the thread so its resources are automatically released
    pthread_detach(pthread_self());
    
    // Call the original handle_client function
    handle_client(args->db, args->client_socket);
    
    // Cleanup
    close(args->client_socket);
    free(args);
    
    return NULL;
}

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;
    pthread_t thread_id;
    sqlite3 *db;

    // Initialize database
    init_database(&db);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Initialize address structure
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {  // Using MAX_CLIENTS instead of hardcoded 3
        perror("listen");
        close(server_fd);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Initialize mutex for thread-safe database operations
    if (pthread_mutex_init(&db_mutex, NULL) != 0) {
        perror("Mutex initialization failed");
        close(server_fd);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Main server loop
    while (1) {
        client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("ERROR: Accept failed");
            continue;
        }

        // Get client IP address for logging
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("New client connected from %s. Creating thread...\n", client_ip);

        // Prepare arguments for the thread
        client_args* args = malloc(sizeof(client_args));
        if (args == NULL) {
            perror("ERROR: Memory allocation failed");
            close(client_socket);
            continue;
        }
        
        args->db = db;
        args->client_socket = client_socket;

        // Create new thread for the client
        if (pthread_create(&thread_id, NULL, thread_handle_client, (void*)args) != 0) {
            perror("ERROR: Thread creation failed");
            close(client_socket);
            free(args);
            continue;
        }

        printf("Thread created successfully for client %s\n", client_ip);
    }

    // Cleanup (this code will only be reached if the while loop is broken)
    pthread_mutex_destroy(&db_mutex);
    sqlite3_close(db);
    close(server_fd);

    return 0;
}