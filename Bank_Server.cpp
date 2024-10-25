//server
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>
#include <sstream>
#include <vector>
#include <cstring>
#include <random>
#include <chrono>
#include <openssl/sha.h>
#include <regex>
#include <mutex>
#include <thread>
#include <fstream>
#include <openssl/aes.h>
void save_auth_file(const std::string &filename);
#define SERVER_PORT 8080
#define PRIVATE_KEY_FILE "private_key.pem"
#define AUTH_FILE "auth.txt"
#define BACKUP_FILE "auth_backup.txt"

// User database with balance: {username -> (password, balance, card_id, account_number)}
std::map<std::string, std::tuple<std::string, double, std::string, std::string>> user_database;
std::mutex user_database_mutex;

// Session token map: {username -> session_token}
std::map<std::string, std::string> session_tokens;
std::mutex session_tokens_mutex;

void log_message(const std::string &msg) {
    std::cout << "[INFO] " << msg << std::endl;
}

void log_error(const std::string &msg) {
    std::cerr << "[ERROR] " << msg << std::endl;
}

// Input validation functions
bool is_valid_username(const std::string &username) {
    // Username should be 3-20 characters, alphanumeric and underscores only
    static const std::regex username_regex("^[a-zA-Z0-9_]{3,20}$");
    return std::regex_match(username, username_regex);
}

bool is_valid_amount(const std::string &amount_str) {
    try {
        double amount = std::stod(amount_str);
        return amount > 0 && amount <= 1000000; // Arbitrary max amount
    } catch (const std::exception&) {
        return false;
    }
}

// Secure error handling
void handle_error(SSL *ssl, const std::string &error_message) {
    log_error(error_message);
    SSL_write(ssl, "An error occurred. Please try again later.", 42);
}

// Base64 decoding function
std::string base64_decode(const std::string &input) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(input.c_str(), input.size());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    std::vector<unsigned char> output(input.size());
    int len = BIO_read(b64, output.data(), input.size());
    BIO_free_all(b64);
    return std::string(output.begin(), output.begin() + len);
}

// RSA decryption function
std::string rsa_decrypt(const std::string &encrypted_base64) {
    std::string encrypted = base64_decode(encrypted_base64);

    FILE *privkey_file = fopen(PRIVATE_KEY_FILE, "rb");
    if (!privkey_file) {
        log_error("Failed to open private key file");
        return "";
    }
    EVP_PKEY *privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);

    if (!privkey) {
        log_error("Failed to read private key");
        return "";
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);

    size_t outlen = 0;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, (const unsigned char *)encrypted.c_str(), encrypted.size());

    std::vector<unsigned char> decrypted(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, (const unsigned char *)encrypted.c_str(), encrypted.size()) <= 0) {
        log_error("Decryption failed");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privkey);

    return std::string(decrypted.begin(), decrypted.end());
}

// Generate random card ID and account number
std::string generate_random_number(int length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9);
    std::string number;
    for (int i = 0; i < length; ++i) {
        number += std::to_string(dis(gen));
    }
    return number;
}
// Hash function to hash the decrypted password on the server side
std::string hash_password_server(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password.c_str(), password.size(), hash);
    return std::string((char*)hash, SHA256_DIGEST_LENGTH);
}

// Function to generate a random session token
std::string generate_session_token() {
    std::string token = generate_random_number(32); // Generate a 32-digit random number
    return token;
}

// Handle account creation with input validation
void handle_create_account(SSL *ssl, const std::string &username, const std::string &encrypted_password, const std::string &initial_amount_str) {
    if (!is_valid_username(username)) {
        handle_error(ssl, "Invalid username format");
        return;
    }

    if (!is_valid_amount(initial_amount_str)) {
        handle_error(ssl, "Invalid initial amount");
        return;
    }

    double initial_amount = std::stod(initial_amount_str);

    std::string decrypted_password = rsa_decrypt(encrypted_password);
    std::string hashed_password = hash_password_server(decrypted_password);

    std::lock_guard<std::mutex> lock(user_database_mutex);
    if (user_database.find(username) != user_database.end()) {
        SSL_write(ssl, "Account already exists", 22);
        log_error("Account creation failed: username already exists");
    } else {
        std::string card_id = generate_random_number(16);
        std::string account_number = generate_random_number(10);
        user_database[username] = {hashed_password, initial_amount, card_id, account_number};
        std::string response = "Account created successfully. Card ID: " + card_id + ", Account Number: " + account_number;
        SSL_write(ssl, response.c_str(), response.size());
        log_message("Account created for username: " + username + " with initial amount: " + std::to_string(initial_amount));

        // Save the updated user database to the auth file
        save_auth_file(AUTH_FILE);
    }
}

// Handle login with input validation
bool handle_login(SSL *ssl, const std::string &username, const std::string &encrypted_password, const std::string &card_id, const std::string &account_number) {
    if (!is_valid_username(username)) {
        handle_error(ssl, "Invalid username format");
        return false;
    }

    std::string decrypted_password = rsa_decrypt(encrypted_password);
    std::string hashed_password = hash_password_server(decrypted_password);
    
    std::lock_guard<std::mutex> lock(user_database_mutex);
    if (user_database.find(username) != user_database.end()) {
        auto &[stored_password, balance, stored_card_id, stored_account_number] = user_database[username];
        if (stored_password == hashed_password && stored_card_id == card_id && stored_account_number == account_number) {
            std::string session_token = generate_session_token();
            {
                std::lock_guard<std::mutex> session_lock(session_tokens_mutex);
                session_tokens[username] = session_token;
            }
            std::string response = "LOGIN_SUCCESS " + session_token;
            SSL_write(ssl, response.c_str(), response.size());
            log_message("Login successful for username: " + username);
            return true;
        } else {
            SSL_write(ssl, "LOGIN_FAILED: Incorrect credentials", 36);
            log_error("Login failed: incorrect credentials for " + username);
        }
    } else {
        SSL_write(ssl, "LOGIN_FAILED: User not found", 28);
        log_error("Login failed: user not found - " + username);
    }
    return false;
}

// Handle transactions with input validation and thread safety
void handle_transaction(SSL *ssl, const std::string &username) {
    char buffer[1024] = {0};
    while (true) {
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            log_error("Failed to read from SSL connection");
            break;
        }
        std::string command(buffer, bytes_read);
        log_message("Received command: " + command);

        std::istringstream iss(command);
        std::string session_token, action;
        iss >> session_token >> action;

        {
            std::lock_guard<std::mutex> lock(session_tokens_mutex);
            if (session_tokens[username] != session_token) {
                SSL_write(ssl, "INVALID_SESSION", 15);
                log_error("Invalid session token for username: " + username);
                break;
            }
        }

        if (action == "LOGOUT") {
            {
                std::lock_guard<std::mutex> lock(session_tokens_mutex);
                session_tokens.erase(username);
            }
            SSL_write(ssl, "Logged out successfully", 24);
            log_message("User logged out: " + username);
            break;
        } else if (action == "CHECK_BALANCE") {
            std::lock_guard<std::mutex> lock(user_database_mutex);
            double balance = std::get<1>(user_database[username]);
            std::string response = "Current balance: " + std::to_string(balance);
            SSL_write(ssl, response.c_str(), response.size());
            log_message("Balance checked for username: " + username + ", Balance: " + std::to_string(balance));
        } else if (action == "DEPOSIT" || action == "WITHDRAW") {
            std::string amount_str;
            iss >> amount_str;
            if (!is_valid_amount(amount_str)) {
                handle_error(ssl, "Invalid amount");
                continue;
            }
            double amount = std::stod(amount_str);

            std::lock_guard<std::mutex> lock(user_database_mutex);
            if (action == "DEPOSIT") {
                std::get<1>(user_database[username]) += amount;
                std::string response = "Deposit successful. New balance: " + std::to_string(std::get<1>(user_database[username]));
                SSL_write(ssl, response.c_str(), response.size());
                log_message("Deposit made for username: " + username + ", Amount: " + std::to_string(amount));
            } else { // WITHDRAW
                if (std::get<1>(user_database[username]) >= amount) {
                    std::get<1>(user_database[username]) -= amount;
                    std::string response = "Withdrawal successful. New balance: " + std::to_string(std::get<1>(user_database[username]));
                    SSL_write(ssl, response.c_str(), response.size());
                    log_message("Withdrawal made for username: " + username + ", Amount: " + std::to_string(amount));
                } else {
                    SSL_write(ssl, "Insufficient balance", 21);
                    log_error("Insufficient balance for username: " + username);
                }
            }

            // Save the updated user database to the auth file
            save_auth_file(AUTH_FILE);
        } else {
            SSL_write(ssl, "Invalid command", 15);
            log_error("Invalid command received: " + action);
        }

        memset(buffer, 0, sizeof(buffer));
    }
}

// SSL context creation
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server_key.pem", SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load certificates");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Add these functions for AES
void derive_aes_key_iv(const std::string &password, unsigned char *aes_key, unsigned char *aes_iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);
    memcpy(aes_key, hash, 32);
    memcpy(aes_iv, hash + 16, 16);
}

std::string aes_decrypt(const std::string &ciphertext, const unsigned char *aes_key, const unsigned char *aes_iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len, plaintext_len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.c_str(), ciphertext.size());
    plaintext_len += len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

// Add these functions for auth file handling
void save_auth_file(const std::string &filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        log_error("Failed to open auth file for writing: " + filename);
        return;
    }

    for (const auto &[username, data] : user_database) {
        const auto &[password, balance, card_id, account_number] = data;
        file << username << " " << password << " " << balance << " " << card_id << " " << account_number << "\n";
    }

    file.close();
    log_message("Auth file saved: " + filename);
}

void load_auth_file(const std::string &filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        log_error("Failed to open auth file for reading: " + filename);
        return;
    }

    user_database.clear();
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string username, password, card_id, account_number;
        double balance;
        if (iss >> username >> password >> balance >> card_id >> account_number) {
            user_database[username] = {password, balance, card_id, account_number};
        }
    }

    file.close();
    log_message("Auth file loaded: " + filename);
}

// Add this function for backup
void create_backup() {
    save_auth_file(BACKUP_FILE);
    log_message("Backup created: " + std::string(BACKUP_FILE));
}

// Main function with improved concurrency
int main() {
    SSL_CTX *ctx = create_ssl_context();

    // Load user database from auth file
    load_auth_file(AUTH_FILE);

    // Create initial backup
    create_backup();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, SOMAXCONN);

    log_message("Server listening on port 8080...");

    while (true) {
        int client_fd = accept(server_fd, NULL, NULL);
        std::thread([client_fd, ctx]() {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);

            if (SSL_accept(ssl) <= 0) {
                log_error("SSL accept failed");
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
                return;
            }

            char buffer[1024] = {0};
            SSL_read(ssl, buffer, sizeof(buffer));
            log_message("Received message: " + std::string(buffer));

            std::string command, username, encrypted_password, card_id, account_number, initial_amount_str;

            std::istringstream iss(buffer);
            iss >> command >> username >> encrypted_password;

            if (command == "CREATE_ACCOUNT") {
                iss >> initial_amount_str;
                handle_create_account(ssl, username, encrypted_password, initial_amount_str);
            } else if (command == "LOGIN") {
                iss >> card_id >> account_number;
                if (handle_login(ssl, username, encrypted_password, card_id, account_number)) {
                    handle_transaction(ssl, username);
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
        }).detach();

        // Create a backup after each successful transaction
        create_backup();
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}