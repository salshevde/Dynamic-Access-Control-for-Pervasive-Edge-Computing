#include "../common/crypto.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#define SERVER_PORT 8080
#define MAX_FILENAME 256
#define MAX_TOKEN_LENGTH 64

typedef struct {
    int socket_fd;
    sqlite3 *db;
} ServerContext;

// Database initialization
int init_database(sqlite3 **db) {
    int rc = sqlite3_open("cloud_storage.db", db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        return rc;
    }

    // Create tables
    const char *owner_table = 
        "CREATE TABLE IF NOT EXISTS owners ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT UNIQUE NOT NULL);"
        
        "CREATE TABLE IF NOT EXISTS files ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "owner_id INTEGER, "
        "filename TEXT, "
        "encrypted_path TEXT, "
        "FOREIGN KEY(owner_id) REFERENCES owners(id));"
        
        "CREATE TABLE IF NOT EXISTS access_tokens ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "file_id INTEGER, "
        "user_token TEXT, "
        "FOREIGN KEY(file_id) REFERENCES files(id));";

    char *err_msg = 0;
    rc = sqlite3_exec(*db, owner_table, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

    return SQLITE_OK;
}

// Register data owner
int register_owner(sqlite3 *db, const char *owner_name) {
    sqlite3_stmt *stmt;
    const char *query = "INSERT INTO owners(name) VALUES (?);";
    
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_text(stmt, 1, owner_name, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

// Store file metadata
int store_file_metadata(sqlite3 *db, int owner_id, 
                        const char *filename, 
                        const char *encrypted_path) {
    sqlite3_stmt *stmt;
    const char *query = "INSERT INTO files(owner_id, filename, encrypted_path) VALUES (?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    if (rc != SQLITE_OK) return rc;

    sqlite3_bind_int(stmt, 1, owner_id);
    sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, encrypted_path, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? sqlite3_last_insert_rowid(db) : -1;
}

// Handle client connections
void *handle_client(void *arg) {
    ServerContext *context = (ServerContext *)arg;
    // Implement connection handling logic
    close(context->socket_fd);
    free(context);
    return NULL;
}

int start_server(sqlite3 *db) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };

    bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_socket, 10);

    while(1) {
        int client_socket = accept(server_socket, NULL, NULL);
        
        ServerContext *context = malloc(sizeof(ServerContext));
        context->socket_fd = client_socket;
        context->db = db;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, context);
        pthread_detach(thread);
    }

    return 0;
}

int main() {
    sqlite3 *db;
    init_database(&db);
    start_server(db);
    sqlite3_close(db);
    return 0;
}