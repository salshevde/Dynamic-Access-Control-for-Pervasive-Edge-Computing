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

typedef struct
{
    sqlite3 *db;
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
                "n_data_classes INT,"
                "public_params BLOB"
                ");"
                "CREATE TABLE IF NOT EXISTS files ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "owner TEXT,"
                "filename TEXT,"
                "data_class INT NOT NULL,"
                "data BLOB,"
                "FOREIGN KEY (owner) REFERENCES owners(username)"
                ");"
                "CREATE TABLE IF NOT EXISTS users ("
                "username TEXT PRIMARY KEY,"
                "password TEXT NOT NULL"
                ");"
                "CREATE TABLE IF NOT EXISTS auth_u ("
                "username TEXT,"
                "ownername TEXT,"
                "data_classes TEXT,"
                "pub_u BLOB,"
                "PRIMARY KEY (username, ownername),"
                "FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,"
                "FOREIGN KEY (ownername) REFERENCES owners(username) ON DELETE CASCADE"
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

    printf("\nwaiting for client.. \n");
    usleep(10000);
    ssize_t bytes_received = recv(socket, buffer, size - 1, 0);

    // printf("%s",buffer);
    if (bytes_received > 0)
    {
        // Remove trailing newline if present
        if (buffer[bytes_received - 1] == '\n')
        {
            buffer[bytes_received - 1] = '\0';
        }
    }
    else
    {
        close(socket);
        return -1;
    }
    return bytes_received;
}

// Helper function to safely send messages
ssize_t send_message(int socket, const char *message)
{

    // printf("\nsending client.. \n");
    usleep(10000);
    printf("\nsending for user %s\n", message);

    return send(socket, message, strlen(message), 0);
}
// Receive file data with size prefix
char *receive_file_data(int socket, int *size)
{
    char size_str[32];
    receive_message(socket, size_str, sizeof(size_str));
    *size = atoi(size_str);
    if (*size == 0)
        return NULL;
    send_message(socket, "Ready");

    char *data = malloc(*size);
    int total = 0, received;
    while (total < *size)
    {
        usleep(10000);

        received = recv(socket, data + total, *size - total, 0);
        if (received <= 0)
            break;
        total += received;
    }
    return data;
}

void send_auth_u(sqlite3 *db, int socket, const char *username, const char *ownername)
{
    usleep(10000); // Optional sleep for timing purposes
    send_message(socket, "auth_u: \n");
    sqlite3_stmt *stmt;
    const char *check_sql = "SELECT data_classes FROM auth_u WHERE username = ? AND ownername = ?";

    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, 0) != SQLITE_OK)
    {

        int error_code = -1;
        send(socket, &error_code, sizeof(error_code), 0);
        return;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ownername, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        const char *data_classes = (const char *)sqlite3_column_text(stmt, 0);

        if (data_classes)
        {
            int len = sqlite3_column_bytes(stmt, 0);

            // Create a properly null-terminated buffer
            char *send_buffer = malloc(len + 2);
            memcpy(send_buffer, data_classes, len);
            send_buffer[len] = '\n';

            send_buffer[len+1] = '\0';

            // Send the null-terminated string
            send_message(socket, send_buffer);
        }
        else
        {
            int error_code = -1;
            send(socket, &error_code, sizeof(error_code), 0);
        }
    }
    else
    {
        int error_code = -1;
        send(socket, &error_code, sizeof(error_code), 0);
    }

    sqlite3_finalize(stmt);
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
        usleep(10000);

        sent = send(socket, data + total, size - total, 0);
        if (sent <= 0)
            break;
        total += sent;
    }
}

void send_owner_public_param(sqlite3 *db, int socket, const char *username, const char *ownername)
{
    usleep(10000);
    send_message(socket, "receiving public param file.. ");

    sqlite3_stmt *stmt;
    const char *check_sql = "SELECT public_params FROM owners WHERE username = ?";
    
    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, 0) != SQLITE_OK)
    {
        int error_code = -1;
        send(socket, &error_code, sizeof(error_code), 0);
        return;
    }

    sqlite3_bind_text(stmt, 1, ownername, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        const void *public_params = sqlite3_column_blob(stmt, 0);
        int blob_size = sqlite3_column_bytes(stmt, 0);

        if (public_params && blob_size > 0)
        {
            send_file_data(socket, (const char *)public_params, blob_size);
        }
        else
        {
            int error_code = -1;
            send(socket, &error_code, sizeof(error_code), 0);
        }
    }
    else
    {
        int error_code = -1;
        send(socket, &error_code, sizeof(error_code), 0);
    }

    sqlite3_finalize(stmt);
}

// Handle authentication
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

int authenticate_user(sqlite3 *db, int client_socket, char *username)
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
        const char *sql = "SELECT password FROM users WHERE username = ?";
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
            close(client_socket);
            break;
        }
    }

    return 0;
}

// Handle owner operations
void handle_owner_operations(sqlite3 *db, int client_socket, const char *username)
{
    char buffer[BUFFER_SIZE];
    char filename[MAX_FILENAME];
    char data_class_str[16];

    int data_class;
    ssize_t sock_status = 1;

    while (sock_status > 0)
    {

        send_message(client_socket, "Choose operation (1: Upload, 2: Delete, 3: Update Params, 4: Update Set, 5: View My File. 6: Connect with a User, 7: Exit): ");
        sock_status = receive_message(client_socket, buffer, sizeof(buffer));
        if (buffer[0] == '1')
        { // Upload
            send_message(client_socket, "Filename: ");
            receive_message(client_socket, filename, sizeof(filename));

            send_message(client_socket, "Data Class: ");
            receive_message(client_socket, data_class_str, sizeof(data_class_str));
            data_class = atoi(data_class_str);
            int size;
            char *file_data = receive_file_data(client_socket, &size);

            sqlite3_stmt *stmt;
            const char *sql = "INSERT INTO files (owner, filename,data_class, data) VALUES (?, ?, ?,?)";
            sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, data_class);
            sqlite3_bind_blob(stmt, 4, file_data, size, SQLITE_STATIC);

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
        }
        else if (buffer[0] == '3')
        { // Update params
            int size;
            char *params_data = receive_file_data(client_socket, &size);

            if (size == 0)
            {
                send_message(client_socket, "Params NOT updated.\n");
            }
            else
            {
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
            }
            free(params_data);
        }
        else if (buffer[0] == '4')
        {
            char target_user[MAX_USERNAME];
            char data_class_action[BUFFER_SIZE];
            int data_class_num;

            send_message(client_socket, "Enter the target username: ");
            receive_message(client_socket, target_user, sizeof(target_user));
            send_message(client_socket, "Enter 'add' or 'remove' followed by the data class number: ");
            receive_message(client_socket, data_class_action, sizeof(data_class_action));
            send_auth_u(db, client_socket, target_user, username);
            char *action = strtok(data_class_action, " ");
            char *data_class_str = strtok(NULL, " ");
            if (!action || !data_class_str || (strcmp(action, "add") != 0 && strcmp(action, "remove") != 0))
            {
                send_message(client_socket, "Invalid input. Use 'add <number>' or 'remove <number>'.\n");
                continue;
            }

            data_class_num = atoi(data_class_str);

            // Check if the row exists: REDUNDANT
            sqlite3_stmt *stmt;
            const char *check_sql = "SELECT data_classes FROM auth_u WHERE username = ? AND ownername = ?";
            sqlite3_prepare_v2(db, check_sql, -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, target_user, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                send_message(client_socket, "UPDATING USER ACCESS");

                // Update existing row
                const char *existing_classes = (const char *)sqlite3_column_text(stmt, 0);
                char updated_classes[BUFFER_SIZE];
                memset(updated_classes, 0, sizeof(updated_classes));

                if (strcmp(action, "add") == 0)
                {
                    // Add the number if not already in the list
                    snprintf(updated_classes, sizeof(updated_classes), "%s", existing_classes);
                    if (!strstr(existing_classes, data_class_str))
                    {
                        if (strlen(existing_classes) > 0)
                        {
                            strncat(updated_classes, ",", sizeof(updated_classes) - strlen(updated_classes) - 1);
                        }
                        strncat(updated_classes, data_class_str, sizeof(updated_classes) - strlen(updated_classes) - 1);
                    }
                }
                else if (strcmp(action, "remove") == 0)
                {
                    // Remove the number from the list
                    char *start, *end;
                    snprintf(updated_classes, sizeof(updated_classes), "%s,", existing_classes); // Add trailing comma for easier parsing
                    start = strstr(updated_classes, data_class_str);
                    if (start)
                    {
                        end = start + strlen(data_class_str);
                        memmove(start, end, strlen(end) + 1); // Shift the rest of the string
                    }
                    updated_classes[strlen(updated_classes) - 1] = '\0'; // Remove the trailing comma
                }

                // Update the table
                const char *update_sql = "UPDATE auth_u SET data_classes = ? WHERE username = (SELECT username FROM users WHERE username = ?) AND ownername = ?";
                sqlite3_prepare_v2(db, update_sql, -1, &stmt, 0);
                sqlite3_bind_text(stmt, 1, updated_classes, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, target_user, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);

                if (sqlite3_step(stmt) == SQLITE_DONE)
                {
                    send_message(client_socket, "Data classes updated successfully.\n");
                }
                else
                {
                    send_message(client_socket, "Error updating data classes.\n");
                }
            }
            else
            {
                send_message(client_socket, "NEW USER");
                // Insert a new row
                const char *insert_sql = "INSERT INTO auth_u (username, ownername, data_classes) VALUES (?, ?, ?)";
                sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);
                sqlite3_bind_text(stmt, 1, target_user, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, data_class_str, -1, SQLITE_STATIC);

                if (sqlite3_step(stmt) == SQLITE_DONE)
                {
                    send_message(client_socket, "New entry added successfully.\n");
                }
                else
                {
                    send_message(client_socket, "Error adding new entry.\n");
                }
            }
            send_message(client_socket, "Done with updates.\n");
        }
        else if (buffer[0] == '5')
        {
            send_message(client_socket, "Enter filename: ");
            receive_message(client_socket, filename, sizeof(filename));

            sqlite3_stmt *stmt;
            const char *sql = "SELECT data FROM files WHERE owner = ? AND filename = ?";
            sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
            printf("filename");
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
        else if (buffer[0] == '6')
        {
            printf("clients talking through direct comms");

            receive_message(client_socket, buffer, sizeof(buffer)); // receive end of direct communication
        }
        else if (buffer[0] == '7')
        { // Exit
            break;
        }
    }
}

// Handle user operations
void handle_user(sqlite3 *db, int client_socket, const char *username)
{
    char owner[MAX_USERNAME];
    char buffer[BUFFER_SIZE];

    char filename[MAX_FILENAME];

    ssize_t sock_status = 1;

    while (sock_status > 0)
    {
        send_message(client_socket, "Choose operation (1: Get Data, 2: Connect with a Owner, 3: Exit): ");
        sock_status = receive_message(client_socket, buffer, sizeof(buffer));
        if (buffer[0] == '1')
        {
            send_message(client_socket, "Enter owner username: ");
            receive_message(client_socket, owner, sizeof(owner));

            send_owner_public_param(db, client_socket, username, owner);

            send_auth_u(db, client_socket, username, owner);

            send_message(client_socket, "Enter filename: ");
            receive_message(client_socket, filename, sizeof(filename));

            sqlite3_stmt *stmt;
            const char *sql = "SELECT data FROM files WHERE owner = ? AND filename = ?";
            sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
            printf("filename");
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
        else if (buffer[0] == '2')
        {

            send_message(client_socket, "Enter owner username: ");
            receive_message(client_socket, owner, sizeof(owner));

            send_owner_public_param(db, client_socket, username, owner);

            receive_message(client_socket, owner, sizeof(owner)); // REceive end of direct communication
        }

        else if (buffer[0] == '3')
        {
            break;
        }
    }
}

// Handle new registration
void handle_new_owner(sqlite3 *db, int client_socket)
{
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char n_data_classes_str[16];
    send_message(client_socket, "New username: ");
    receive_message(client_socket, username, sizeof(username));

    send_message(client_socket, "New password: ");
    receive_message(client_socket, password, sizeof(password));

    send_message(client_socket, "Number of data classes: ");
    receive_message(client_socket, n_data_classes_str, sizeof(n_data_classes_str));
    int n_data_classes = atoi(n_data_classes_str);

    send_message(client_socket, "Send public params file (size in bytes): ");
    int size;
    char *params_data = receive_file_data(client_socket, &size);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO owners (username, password, n_data_classes,  public_params) VALUES (?, ?,?, ?)";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, n_data_classes);
    sqlite3_bind_blob(stmt, 4, params_data, size, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        send_message(client_socket, "Error creating account.\n");
    }
    else
    {
        send_message(client_socket, "Account created successfully.\n");

        handle_owner_operations(db, client_socket, username);
    }

    sqlite3_finalize(stmt);
    free(params_data);
}

void handle_new_user(sqlite3 *db, int client_socket)
{
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char n_data_classes_str[16];
    send_message(client_socket, "New username: ");
    receive_message(client_socket, username, sizeof(username));

    send_message(client_socket, "New password: ");
    receive_message(client_socket, password, sizeof(password));

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        send_message(client_socket, "Error creating account.\n");
    }
    else
    {
        send_message(client_socket, "Account created successfully.\n");
        handle_user(db, client_socket, username);
    }

    sqlite3_finalize(stmt);
}

// Main client handler
void handle_client(sqlite3 *db, int client_socket)
{
    char buffer[BUFFER_SIZE];
    char username[MAX_USERNAME];

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

    if (buffer[0] == '1')
    { // Owner
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

        if (buffer[0] == '1')
        { // Sign in

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

        if (send_message(client_socket, "1: Sign in, 2: Create new: ") <= 0)
        {
            printf("ERROR: Failed to send user options\n");
            return;
        }

        bytes_received = receive_message(client_socket, buffer, sizeof(buffer));
        if (bytes_received <= 0)
        {
            printf("ERROR: Failed to receive user option\n");
            return;
        }

        if (buffer[0] == '1')
        { // Sign in

            if (authenticate_user(db, client_socket, username))
            {
                handle_user(db, client_socket, username);
            }
            else
            {
                printf("ERROR: User authentication failed\n");
            }
        }
        else if (buffer[0] == '2')
        { // Create new
            handle_new_user(db, client_socket);
        }
        else
        {
            printf("ERROR: Invalid user option selected: %c\n", buffer[0]);
        }
    }
    else
    {
        printf("ERROR: Invalid interface selection: %c\n", buffer[0]);
    }
}

// threaded
void *thread_handle_client(void *arg)
{
    client_args *args = (client_args *)arg;

    // Detach the thread so its resources are automatically released
    pthread_detach(pthread_self());

    // Call the original handle_client function
    handle_client(args->db, args->client_socket);

    // Cleanup
    printf("\nClosing connection with client");
    close(args->client_socket);
    free(args);

    return NULL;
}

int main()
{
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
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Initialize address structure
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        close(server_fd);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0)
    { // Using MAX_CLIENTS instead of hardcoded 3
        perror("listen");
        close(server_fd);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Initialize mutex for thread-safe database operations
    if (pthread_mutex_init(&db_mutex, NULL) != 0)
    {
        perror("Mutex initialization failed");
        close(server_fd);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Main server loop
    while (1)
    {
        client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0)
        {
            perror("ERROR: Accept failed");
            continue;
        }

        // Get client IP address for logging
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("New client connected from %s. Creating thread...\n", client_ip);

        // Prepare arguments for the thread
        client_args *args = malloc(sizeof(client_args));
        if (args == NULL)
        {
            perror("ERROR: Memory allocation failed");
            close(client_socket);
            continue;
        }

        args->db = db;
        args->client_socket = client_socket;

        // Create new thread for the client
        if (pthread_create(&thread_id, NULL, thread_handle_client, (void *)args) != 0)
        {
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