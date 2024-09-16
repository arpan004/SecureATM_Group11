#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_SQL_LENGTH 1000
#define MAX_BUFFER_SIZE 1024
#define PORT 8080

sqlite3 *db;
char *zErrMsg = 0;

void execute_sql(const char *sql, char *result, size_t result_size) {
    int rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        snprintf(result, result_size, "SQL error: %s", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        snprintf(result, result_size, "Operation successful");
    }
}

void initialize_database() {
    int rc = sqlite3_open("bank.db", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(0);
    }

    const char *sql_create_accounts = "CREATE TABLE IF NOT EXISTS accounts ("
                                      "account_number INTEGER PRIMARY KEY,"
                                      "name TEXT NOT NULL,"
                                      "balance REAL NOT NULL);";

    const char *sql_create_transactions = "CREATE TABLE IF NOT EXISTS transactions ("
                                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                          "account_number INTEGER,"
                                          "type TEXT NOT NULL,"
                                          "amount REAL NOT NULL,"
                                          "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);";

    char result[MAX_BUFFER_SIZE];
    execute_sql(sql_create_accounts, result, sizeof(result));
    execute_sql(sql_create_transactions, result, sizeof(result));
}

int generate_account_number() {
    return 1000000 + rand() % 9000000;
}

void create_account(const char *name, char *result, size_t result_size) {
    int account_number;
    char sql[MAX_SQL_LENGTH];

    do {
        account_number = generate_account_number();
        snprintf(sql, MAX_SQL_LENGTH, "SELECT * FROM accounts WHERE account_number = %d;", account_number);
    } while (sqlite3_exec(db, sql, NULL, 0, &zErrMsg) == SQLITE_ROW);

    snprintf(sql, MAX_SQL_LENGTH, "INSERT INTO accounts (account_number, name, balance) VALUES (%d, '%s', 0.0);", account_number, name);
    execute_sql(sql, result, result_size);

    snprintf(result, result_size, "Account created successfully. Account number: %d", account_number);
}

void deposit(int account_number, double amount, char *result, size_t result_size) {
    char sql[MAX_SQL_LENGTH];

    snprintf(sql, MAX_SQL_LENGTH, "UPDATE accounts SET balance = balance + %.2f WHERE account_number = %d;", amount, account_number);
    execute_sql(sql, result, result_size);

    snprintf(sql, MAX_SQL_LENGTH, "INSERT INTO transactions (account_number, type, amount) VALUES (%d, 'Deposit', %.2f);", account_number, amount);
    execute_sql(sql, result, result_size);

    snprintf(result, result_size, "Deposit successful");
}

void withdraw(int account_number, double amount, char *result, size_t result_size) {
    char sql[MAX_SQL_LENGTH];

    snprintf(sql, MAX_SQL_LENGTH, "SELECT balance FROM accounts WHERE account_number = %d;", account_number);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            double balance = sqlite3_column_double(stmt, 0);
            if (balance >= amount) {
                snprintf(sql, MAX_SQL_LENGTH, "UPDATE accounts SET balance = balance - %.2f WHERE account_number = %d;", amount, account_number);
                execute_sql(sql, result, result_size);

                snprintf(sql, MAX_SQL_LENGTH, "INSERT INTO transactions (account_number, type, amount) VALUES (%d, 'Withdrawal', %.2f);", account_number, amount);
                execute_sql(sql, result, result_size);

                snprintf(result, result_size, "Withdrawal successful");
            } else {
                snprintf(result, result_size, "Insufficient funds");
            }
        } else {
            snprintf(result, result_size, "Account not found");
        }
    }
    sqlite3_finalize(stmt);
}

void get_transactions(int account_number, char *result, size_t result_size) {
    char sql[MAX_SQL_LENGTH];
    snprintf(sql, MAX_SQL_LENGTH, "SELECT * FROM transactions WHERE account_number = %d ORDER BY timestamp;", account_number);
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        char *ptr = result;
        size_t remaining = result_size;
        int written = snprintf(ptr, remaining, "Transactions for account %d:\n", account_number);
        ptr += written;
        remaining -= written;

        while (sqlite3_step(stmt) == SQLITE_ROW && remaining > 0) {
            const char *type = (const char *)sqlite3_column_text(stmt, 2);
            double amount = sqlite3_column_double(stmt, 3);
            const char *timestamp = (const char *)sqlite3_column_text(stmt, 4);
            written = snprintf(ptr, remaining, "%s - %s: %.2f\n", timestamp, type, amount);
            ptr += written;
            remaining -= written;
        }
    }
    sqlite3_finalize(stmt);
}

void handle_client(int client_socket) {
    char buffer[MAX_BUFFER_SIZE] = {0};
    char response[MAX_BUFFER_SIZE] = {0};

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(response, 0, sizeof(response));

        int valread = read(client_socket, buffer, MAX_BUFFER_SIZE);
        if (valread <= 0) {
            break;
        }

        char command[20];
        int account_number;
        double amount;
        char name[50];

        if (sscanf(buffer, "%s", command) == 1) {
            if (strcmp(command, "CREATE") == 0) {
                if (sscanf(buffer, "%*s %s", name) == 1) {
                    create_account(name, response, sizeof(response));
                }
            } else if (strcmp(command, "DEPOSIT") == 0) {
                if (sscanf(buffer, "%*s %d %lf", &account_number, &amount) == 2) {
                    deposit(account_number, amount, response, sizeof(response));
                }
            } else if (strcmp(command, "WITHDRAW") == 0) {
                if (sscanf(buffer, "%*s %d %lf", &account_number, &amount) == 2) {
                    withdraw(account_number, amount, response, sizeof(response));
                }
            } else if (strcmp(command, "TRANSACTIONS") == 0) {
                if (sscanf(buffer, "%*s %d", &account_number) == 1) {
                    get_transactions(account_number, response, sizeof(response));
                }
            } else if (strcmp(command, "EXIT") == 0) {
                strcpy(response, "Goodbye!");
                send(client_socket, response, strlen(response), 0);
                break;
            } else {
                strcpy(response, "Invalid command");
            }
        }

        send(client_socket, response, strlen(response), 0);
    }

    close(client_socket);
}

int main() {
    srand(time(NULL));
    initialize_database();

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Bank server is running on port %d\n", PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        printf("New client connected: %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        pid_t pid = fork();
        if (pid == 0) {
            close(server_fd);
            handle_client(new_socket);
            exit(0);
        } else {
            close(new_socket);
        }
    }

    sqlite3_close(db);
    return 0;
}