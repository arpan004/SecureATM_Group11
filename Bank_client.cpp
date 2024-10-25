//client
#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/aes.h>
void transaction_window(SSL *ssl);
#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"
#define PUBLIC_KEY_FILE "public_key.pem"

std::string session_token; // Global variable to store session token


// Logging utilities
void log_message(const std::string &message) {
    std::cout << "[INFO] " << message << std::endl;
}

void log_error(const std::string &message) {
    std::cerr << "[ERROR] " << message << std::endl;
}

// Base64 encoding function
std::string base64_encode(const std::string &input) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input.data(), input.size());
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string encoded(bptr->data, bptr->length);
    BIO_free_all(b64);

    return encoded;
}

// RSA encryption function
std::string rsa_encrypt(const std::string &plaintext) {
    FILE *pubkey_file = fopen(PUBLIC_KEY_FILE, "rb");
    if (!pubkey_file) {
        log_error("Failed to open public key file");
        return "";
    }
    EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);

    if (!pubkey) {
        log_error("Failed to read public key");
        return "";
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_encrypt_init(ctx);

    size_t outlen = 0;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char *)plaintext.c_str(), plaintext.size());

    std::vector<unsigned char> encrypted(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, (const unsigned char *)plaintext.c_str(), plaintext.size()) <= 0) {
        log_error("Encryption failed");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    return base64_encode(std::string(encrypted.begin(), encrypted.end()));
}

// SSL context creation
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Establish SSL connection
SSL *establish_ssl_connection(SSL_CTX *ctx) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("Failed to create socket");
        return nullptr;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Failed to connect to server");
        close(sock);
        return nullptr;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        log_error("SSL connection failed");
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }

    log_message("SSL connection established");
    return ssl;
}
// SHA-256 hash function
std::string hash_password(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password.c_str(), password.size(), hash);
    
    return std::string((char*)hash, SHA256_DIGEST_LENGTH);
}

// Add these functions for AES
void derive_aes_key_iv(const std::string &password, unsigned char *aes_key, unsigned char *aes_iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);
    memcpy(aes_key, hash, 32);
    memcpy(aes_iv, hash + 16, 16);
}

std::string aes_encrypt(const std::string &plaintext, const unsigned char *aes_key, const unsigned char *aes_iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

// Modify the create_account function to use AES encryption
void create_account(SSL *ssl) {
    std::string username, password;
    double initial_amount;

    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;
    std::cout << "Enter initial amount: ";
    std::cin >> initial_amount;
    
    // Hash the password before encrypting
    std::string hashed_password = hash_password(password);

    // Derive AES key and IV from the password
    unsigned char aes_key[32], aes_iv[16];
    derive_aes_key_iv(password, aes_key, aes_iv);

    // Encrypt the password with AES
    std::string encrypted_password = aes_encrypt(hashed_password, aes_key, aes_iv);

    // Encrypt the AES-encrypted password with RSA
    std::string rsa_encrypted_password = rsa_encrypt(encrypted_password);

    std::string message = "CREATE_ACCOUNT " + username + " " + rsa_encrypted_password + " " + std::to_string(initial_amount);

    SSL_write(ssl, message.c_str(), message.size());

    char buffer[1024] = {0};
    SSL_read(ssl, buffer, sizeof(buffer));
    log_message("Server response: " + std::string(buffer));
}

// Modify the login function to use AES encryption
void login(SSL *ssl) {
    std::string username, password, card_id, account_number;

    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;
    std::cout << "Enter card ID: ";
    std::cin >> card_id;
    std::cout << "Enter account number: ";
    std::cin >> account_number;
    
    // Hash the password before encrypting
    std::string hashed_password = hash_password(password);

    // Derive AES key and IV from the password
    unsigned char aes_key[32], aes_iv[16];
    derive_aes_key_iv(password, aes_key, aes_iv);

    // Encrypt the password with AES
    std::string encrypted_password = aes_encrypt(hashed_password, aes_key, aes_iv);

    // Encrypt the AES-encrypted password with RSA
    std::string rsa_encrypted_password = rsa_encrypt(encrypted_password);

    std::string message = "LOGIN " + username + " " + rsa_encrypted_password + " " + card_id + " " + account_number;

    SSL_write(ssl, message.c_str(), message.size());

    char buffer[1024] = {0};
    SSL_read(ssl, buffer, sizeof(buffer));
    std::string response(buffer);

    if (response.rfind("LOGIN_SUCCESS", 0) == 0) {
        session_token = response.substr(14); // Extract session token
        log_message("Login successful");
        transaction_window(ssl);
    } else {
        log_error("Login failed: " + response);
    }
}

// Transaction window
void transaction_window(SSL *ssl) {
    while (true) {
        std::cout << "\n1. Check Balance\n2. Deposit\n3. Withdraw\n4. Logout\nEnter your choice: ";
        int choice;
        std::cin >> choice;

        std::string message = session_token + " "; // Prepend session token to message
        switch (choice) {
            case 1:
                message += "CHECK_BALANCE";
                break;
            case 2: {
                std::cout << "Enter amount to deposit: ";
                double amount;
                std::cin >> amount;
                message += "DEPOSIT " + std::to_string(amount);
                break;
            }
            case 3: {
                std::cout << "Enter amount to withdraw: ";
                double amount;
                std::cin >> amount;
                message += "WITHDRAW " + std::to_string(amount);
                break;
            }
            case 4:
                message += "LOGOUT";
                SSL_write(ssl, message.c_str(), message.size());
                session_token.clear(); // Clear session token
                return;
            default:
                log_error("Invalid choice, please try again.");
                continue;
        }

        if (SSL_write(ssl, message.c_str(), message.size()) <= 0) {
            log_error("Failed to send message to server");
            return;
        }

        char buffer[1024] = {0};
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            log_error("Failed to read from server");
            return;
        }
        log_message("Server response: " + std::string(buffer, bytes_read));
    }
}



// Main function
int main() {
    SSL_CTX *ctx = create_ssl_context();

    while (true) {
        SSL *ssl = establish_ssl_connection(ctx);
        if (!ssl) return -1;

        std::cout << "\n1. Create Account\n2. Login\n3. Exit\nEnter your choice: ";
        int choice;
        std::cin >> choice;

        switch (choice) {
            case 1:
                create_account(ssl);
                break;
            case 2:
                login(ssl);
                break;
            case 3:
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                log_message("Exiting...");
                return 0;
            default:
                log_error("Invalid choice, please try again.");
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    SSL_CTX_free(ctx);
    return 0;
}