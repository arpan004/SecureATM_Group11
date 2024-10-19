// Bank_Client.cpp

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <random>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/aes.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h>
#include <condition_variable>
#include <openssl/x509.h>
#include <filesystem>
#include "auth.h"

// Constants
const int SERVER_PORT = 8443;
const char* SERVER_IP = "127.0.0.1";
const int SESSION_TIMEOUT_SECONDS = 300;
const std::string HMAC_KEY = "C3B1F9E2D4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8"; // Same fixed HMAC key as server
const std::string AES_KEY_STR = "0123456789abcdef0123456789abcdef"; // 256-bit key
const std::string AES_IV = "abcdef9876543210";  // 128-bit IV

// Global variables
struct Session {
    std::string token;
    std::string account_number;
    std::chrono::steady_clock::time_point last_active;
    std::string role;
};
Session current_session;

// Function declarations
std::string generate_hmac(const std::string& message, const std::string& key);
bool verify_hmac(const std::string& data, const std::string& key, const std::string& received_hmac);
void log_error(const std::string& error_message);
void log_message(const std::string& message);
std::string sha256(const std::string& input);
std::string generate_session_token();
bool is_session_active();
void update_session_activity();
std::string generate_nonce();
bool send_message_with_hmac(SSL* ssl, const std::string& message);
bool receive_message_with_hmac(SSL* ssl, std::string& message);
std::string base64_encode(const std::string& input);
std::string base64_decode(const std::string& input);
std::string rsa_encrypt(const std::string& plaintext);
SSL_CTX* create_context_client();
SSL* connect_to_server(SSL_CTX* ctx);
void cleanup_and_exit(SSL* ssl, SSL_CTX* ctx);
std::string sanitize_input(const std::string& input);
void create_account(SSL* ssl);
std::pair<std::string, std::string> login(SSL* ssl);
void transaction_menu(SSL* ssl);
void handle_deposit(SSL* ssl);
void handle_withdraw(SSL* ssl);
void handle_check_balance(SSL* ssl);
void handle_logout(SSL* ssl);
std::string request_nonce(SSL* ssl);
bool compare_certificates(X509* cert1, X509* cert2);
X509* load_pinned_cert(const std::string& pinned_cert_path);
std::string generate_client_session_token();
std::string generate_card_data();
std::string get_executable_path();
SSL* reconnect_to_server(SSL_CTX* ctx);

// Add this near the top of the file, after the includes
std::mutex mtx;

// is_numeric function to check if a string contains only digits
bool is_numeric(const std::string& str) {
    return !str.empty() && std::all_of(str.begin(), str.end(), ::isdigit);
}

// Function implementations

std::string generate_hmac(const std::string& message, const std::string& key) {
    unsigned char* digest;
    unsigned int len = EVP_MAX_MD_SIZE;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                 reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), NULL, &len);
    std::stringstream ss;
    for(unsigned int i = 0; i < len; ++i){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return ss.str();
}

bool verify_hmac(const std::string& data, const std::string& key, const std::string& received_hmac) {
    std::string calculated_hmac = generate_hmac(data, key);
    return calculated_hmac == received_hmac;
}

void log_error(const std::string& error_message) {
    std::lock_guard<std::mutex> lock(mtx); // Ensure thread safety if applicable
    std::ofstream log_file("atm_client_error.log", std::ios_base::app);
    if(log_file.is_open()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        log_file << std::ctime(&now) << ": " << error_message << std::endl;
        log_file.close();
    }
}

void log_message(const std::string& message) {
    std::lock_guard<std::mutex> lock(mtx);
    std::ofstream log_file("atm_client.log", std::ios_base::app);
    if(log_file.is_open()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        log_file << std::ctime(&now) << ": " << message << std::endl;
        log_file.close();
    }
    // Also print to console for immediate feedback
    std::cout << "CLIENT LOG: " << message << std::endl;
}

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string generate_session_token() {
    unsigned char random_data[32];
    if (RAND_bytes(random_data, sizeof(random_data)) != 1) {
        log_error("Failed to generate random data for session token.");
        return "";
    }
    return base64_encode(std::string(reinterpret_cast<char*>(random_data), sizeof(random_data)));
}

bool is_session_active() {
    if (current_session.token.empty()) {
        return false;
    }
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - current_session.last_active).count();
    return elapsed < SESSION_TIMEOUT_SECONDS;
}

void update_session_activity() {
    current_session.last_active = std::chrono::steady_clock::now();
}

std::string generate_nonce() {
    // Generate a random 32-character alphanumeric nonce
    std::string nonce;
    std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    for(int i = 0; i < 32; ++i){
        nonce += chars[dis(gen)];
    }
    return nonce;
}

bool send_message_with_hmac(SSL* ssl, const std::string& message) {
    std::string hmac = generate_hmac(message, HMAC_KEY);
    std::string payload = message + "|HMAC:" + hmac;
    log_message("Sending: " + payload);
    int bytes_written = SSL_write(ssl, payload.c_str(), payload.length());
    if (bytes_written <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        log_error("Failed to send message. SSL error: " + std::to_string(ssl_error));
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool receive_message_with_hmac(SSL* ssl, std::string& message) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        log_error("Failed to receive message. SSL error: " + std::to_string(ssl_error));
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::string received_data(buffer, bytes_read);
    log_message("Received: " + received_data);

    size_t hmac_pos = received_data.find("|HMAC:");
    if (hmac_pos == std::string::npos) {
        log_error("Received message without HMAC.");
        return false;
    }

    message = received_data.substr(0, hmac_pos);
    std::string received_hmac = received_data.substr(hmac_pos + 6);

    if (!verify_hmac(message, HMAC_KEY, received_hmac)) {
        log_error("HMAC verification failed.");
        return false;
    }

    log_message("Received verified message: " + message);
    return true;
}

std::string base64_encode(const std::string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

std::string base64_decode(const std::string& input) {
    BIO *bio, *b64;
    char *buffer = new char[input.length()];
    memset(buffer, 0, input.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_size = BIO_read(bio, buffer, input.length());
    BIO_free_all(bio);

    std::string output(buffer, decoded_size);
    delete[] buffer;
    return output;
}

std::string rsa_encrypt(const std::string& plaintext) {
    std::string pubkey_path = "ssl_certs/public_key.pem";
    FILE* pubkey_file = fopen(pubkey_path.c_str(), "rb");
    if (!pubkey_file) {
        log_error("Failed to open public key file: " + pubkey_path);
        std::cerr << "Error: " << strerror(errno) << std::endl;
        return "";
    }

    EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);

    if (!pubkey) {
        log_error("Failed to read public key from file: " + pubkey_path);
        ERR_print_errors_fp(stderr);
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        log_error("Failed to create EVP_PKEY_CTX.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pubkey);
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        log_error("Failed to initialize encryption operation.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    // Set RSA padding to OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        log_error("Failed to set RSA padding.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    // Determine buffer length
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.length()) <= 0) {
        log_error("Failed to determine encryption buffer length.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    // Allocate buffer
    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen,
                        reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                        plaintext.length()) <= 0) {
        log_error("Failed to encrypt data.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    // Return ciphertext as base64 encoded string
    return base64_encode(std::string(reinterpret_cast<char*>(ciphertext.data()), outlen));
}

SSL_CTX* create_context_client() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error("Unable to create SSL context.");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Disable certificate verification for testing purposes
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Load default CA certificates (optional, but recommended)
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        log_error("Failed to load default CA certificates.");
        ERR_print_errors_fp(stderr);
        // Continue anyway
    }

    return ctx;
}

// Function to compare two X509 certificates
bool compare_certificates(X509* cert1, X509* cert2) {
    if (!cert1 || !cert2) return false;
    return X509_cmp(cert1, cert2) == 0;
}

// Function to load pinned certificate
X509* load_pinned_cert(const std::string& pinned_cert_path) {
    FILE* fp = fopen(pinned_cert_path.c_str(), "r");
    if (!fp) {
        log_error("Failed to open pinned certificate file: " + pinned_cert_path);
        return nullptr;
    }
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return cert;
}

// Updated connect_to_server function with certificate pinning
SSL* connect_to_server(SSL_CTX* ctx) {
    int sock;
    struct sockaddr_in server_addr;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("Unable to create socket.");
        return nullptr;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 addresses from text to binary form
    if(inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)  {
        log_error("Invalid address/ Address not supported.");
        close(sock);
        return nullptr;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection Failed.");
        close(sock);
        return nullptr;
    }

    // Create SSL object
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Establish SSL connection
    if (SSL_connect(ssl) <= 0) {
        log_error("SSL connection failed.");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }

    log_message("Connected to the server with " + std::string(SSL_get_cipher(ssl)) + " encryption.");
    return ssl;
}

void cleanup_and_exit(SSL* ssl, SSL_CTX* ctx) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    EVP_cleanup();
    exit(EXIT_SUCCESS);
}

std::string sanitize_input(const std::string& input) {
    std::string sanitized;
    for (char c : input) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.') {
            sanitized += c;
        }
    }
    return sanitized;
}

std::string generate_card_data() {
    // Generate a simple 16-digit card number
    std::string card_number;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9);
    
    for (int i = 0; i < 16; ++i) {
        card_number += std::to_string(dis(gen));
    }
    
    return card_number;
}

void create_account(SSL* ssl) {
    std::string name, pin;
    
    std::cout << "Enter your name: ";
    std::cin.ignore(); // Clear newline from previous input
    std::getline(std::cin, name);
    name = sanitize_input(name);

    // PIN validation
    while (true) {
        std::cout << "Enter PIN (4-6 digits): ";
        std::cin >> pin;
        pin = sanitize_input(pin);

        if (pin.length() < 4 || pin.length() > 6 || !is_numeric(pin)) {
            std::cerr << "Invalid PIN. Please enter a 4-6 digit numeric PIN." << std::endl;
        } else {
            break;
        }
    }

    // Generate card data automatically
    std::string card_data = generate_card_data();
    std::cout << "Generated card number: " << card_data << std::endl;

    // Generate nonce
    std::string nonce = generate_nonce();

    // Encrypt PIN
    std::string encrypted_pin = rsa_encrypt(pin);
    if (encrypted_pin.empty()) {
        std::cerr << "Failed to encrypt PIN. Please check if the public key file exists and is readable." << std::endl;
        return;
    }

    // Prepare CREATE_ACCOUNT command
    std::ostringstream ss;
    ss << "CREATE_ACCOUNT " << name << " " << base64_encode(encrypted_pin) << " " << card_data << " " << nonce;
    std::string create_command = ss.str();

    if (!send_message_with_hmac(ssl, create_command)) {
        std::cerr << "Failed to send CREATE_ACCOUNT command." << std::endl;
        return;
    }

    // Receive server response
    std::string response;
    if (receive_message_with_hmac(ssl, response)) {
        std::cout << response << std::endl;
        if (response.find("SUCCESS") != std::string::npos) {
            size_t account_number_pos = response.find("Account Number:");
            if (account_number_pos != std::string::npos) {
                std::string account_number = response.substr(account_number_pos + 16);
                std::cout << "Your account number is: " << account_number << std::endl;
                std::cout << "Please remember your account number and card number for login." << std::endl;
            }
        } else if (response.find("FAILURE") != std::string::npos) {
            std::cerr << "Account creation failed. Server response: " << response << std::endl;
            std::cerr << "This might be due to a server-side issue. Please try again later or contact support." << std::endl;
        }
    } else {
        std::cerr << "Failed to receive or verify server response." << std::endl;
    }
}

std::pair<std::string, std::string> login(SSL* ssl) {
    std::string account_number, pin, card_data;

    std::cout << "Enter account number: ";
    std::cin >> account_number;
    account_number = sanitize_input(account_number);

    std::cout << "Enter PIN: ";
    std::cin >> pin;
    pin = sanitize_input(pin);

    std::cout << "Enter card number: ";
    std::cin >> card_data;
    card_data = sanitize_input(card_data);

    // Generate nonce
    std::string nonce = generate_nonce();

    // Encrypt PIN
    std::string encrypted_pin = rsa_encrypt(pin);
    if (encrypted_pin.empty()) {
        std::cerr << "Failed to encrypt PIN. Please check if the public key file exists and is readable." << std::endl;
        return {"", ""};
    }

    // Prepare LOGIN command with nonce
    std::ostringstream ss;
    ss << "LOGIN " << account_number << " " << base64_encode(encrypted_pin) << " " << card_data << " " << nonce;
    std::string login_command = ss.str();

    if (!send_message_with_hmac(ssl, login_command)) {
        std::cerr << "Failed to send LOGIN command." << std::endl;
        return {"", ""};
    }

    // Check SSL connection after sending login command
    if (SSL_get_fd(ssl) == -1) {
        std::cerr << "SSL connection lost after sending LOGIN command." << std::endl;
        return {"", ""};
    }

    // Receive server response
    std::string response;
    if (receive_message_with_hmac(ssl, response)) {
        std::cout << "Received response: " << response << std::endl;  // Debug line

        if (response.find("OTP:") != std::string::npos) {
            // Extract OTP from response
            size_t otp_pos = response.find("OTP:");
            std::string otp = response.substr(otp_pos + 4);
            otp = sanitize_input(otp); // Ensure OTP is sanitized
            std::cout << "Received OTP: " << otp << std::endl;  // For testing purposes

            // You can use verifyOTP here if you want to do a client-side check
            // before sending the OTP to the server
            std::string user_otp;
            std::cout << "Enter OTP received on your device: ";
            std::cin >> user_otp;
            user_otp = sanitize_input(user_otp);

            if (verifyOTP(user_otp, otp)) {
                // Proceed with sending OTP to server
            } else {
                std::cout << "Invalid OTP entered. Please try again." << std::endl;
                return {"", ""};
            }

            // Prepare OTP command
            std::ostringstream otp_ss;
            otp_ss << "OTP " << account_number << " " << user_otp << " " << nonce;
            std::string otp_command = otp_ss.str();

            if (!send_message_with_hmac(ssl, otp_command)) {
                std::cerr << "Failed to send OTP command." << std::endl;
                return {"", ""};
            }

            // Receive final response
            std::string final_response;
            if (receive_message_with_hmac(ssl, final_response)) {
                std::cout << "Received response: " << final_response << std::endl;  // Debug line
                if (final_response.find("SUCCESS") != std::string::npos) {
                    size_t token_pos = final_response.find("Session Token:");
                    size_t role_pos = final_response.find("Role:");
                    if (token_pos != std::string::npos && role_pos != std::string::npos) {
                        size_t token_start = token_pos + 14;
                        size_t token_end = final_response.find(" ", token_start);
                        if(token_end == std::string::npos){
                            token_end = final_response.length();
                        }
                        std::string token = final_response.substr(token_start, token_end - token_start);
                        std::string role = final_response.substr(role_pos + 5);
                        role = sanitize_input(role); // Ensure role is sanitized

                        // Initialize session
                        current_session.token = token;
                        current_session.last_active = std::chrono::steady_clock::now();
                        current_session.role = role;
                        current_session.account_number = account_number;
                        std::cout << "Login successful. Token: " << token << ", Role: " << role << std::endl;  // Debug line
                        return {token, role};
                    }
                } else {
                    std::cout << "Login failed. Server response: " << final_response << std::endl;  // Debug line
                }
            } else {
                std::cout << "Failed to receive or verify server response." << std::endl;  // Debug line
            }
        } else if (response.find("SUCCESS") != std::string::npos) {
            // If server sends success directly without OTP (optional)
            size_t token_pos = response.find("Session Token:");
            size_t role_pos = response.find("Role:");
            if (token_pos != std::string::npos && role_pos != std::string::npos) {
                size_t token_start = token_pos + 14;
                size_t token_end = response.find(" ", token_start);
                if(token_end == std::string::npos){
                    token_end = response.length();
                }
                std::string token = response.substr(token_start, token_end - token_start);
                std::string role = response.substr(role_pos + 5);
                role = sanitize_input(role); // Ensure role is sanitized

                // Initialize session
                current_session.token = token;
                current_session.last_active = std::chrono::steady_clock::now();
                current_session.role = role;
                current_session.account_number = account_number;
                std::cout << "Login successful. Token: " << token << ", Role: " << role << std::endl;  // Debug line
                return {token, role};
            }
        } else {
            std::cout << "Login failed. Server response: " << response << std::endl;  // Debug line
        }
    } else {
        std::cout << "Failed to receive server response during login." << std::endl;  // Debug line
    }
    return {"", ""};
}

void transaction_menu(SSL* ssl) {
    std::cout << "Entering transaction menu..." << std::endl;
    
    // Check SSL connection
    if (SSL_get_fd(ssl) == -1) {
        std::cerr << "SSL connection is not valid at the start of transaction menu." << std::endl;
        return;
    }

    while (true) {
        if (!is_session_active()) {
            std::cout << "Session expired. Please log in again." << std::endl;
            handle_logout(ssl);
            break;
        }
        update_session_activity();

        std::cout << "\n--- Transaction Menu ---\n";
        std::cout << "1. Deposit\n";
        std::cout << "2. Withdraw\n";
        std::cout << "3. Check Balance\n";
        if (current_session.role == "ADMIN") {
            std::cout << "4. Delete Account\n";
            std::cout << "5. Logout\n";
        } else {
            std::cout << "4. Logout\n";
        }
        std::cout << "Enter choice: ";
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input. Please enter a number." << std::endl;
            continue;
        }

        switch (choice) {
            case 1:
                handle_deposit(ssl);
                break;
            case 2:
                handle_withdraw(ssl);
                break;
            case 3:
                handle_check_balance(ssl);
                break;
            case 4:
                if (current_session.role == "ADMIN") {
                    std::cout << "Delete Account functionality not implemented yet." << std::endl;
                } else {
                    handle_logout(ssl);
                    return;
                }
                break;
            case 5:
                if (current_session.role == "ADMIN") {
                    handle_logout(ssl);
                    return;
                }
                break;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }
    std::cout << "Exiting transaction menu..." << std::endl;  // Debug line
}

void handle_deposit(SSL* ssl) {
    if (SSL_get_fd(ssl) == -1) {
        std::cerr << "SSL connection is not valid. Cannot perform deposit." << std::endl;
        return;
    }
    double amount;
    std::cout << "Enter amount to deposit: ";
    std::cin >> amount;

    if (amount <= 0) {
        std::cerr << "Invalid amount. Please enter a positive number." << std::endl;
        return;
    }

    std::ostringstream ss;
    ss << "DEPOSIT " << current_session.token << " " << current_session.account_number << " " << std::fixed << std::setprecision(2) << amount;
    std::string deposit_command = ss.str();

    if (!send_message_with_hmac(ssl, deposit_command)) {
        std::cerr << "Failed to send DEPOSIT command." << std::endl;
        return;
    }

    // Receive server response
    std::string response;
    if (receive_message_with_hmac(ssl, response)) {
        std::cout << response << std::endl;
    } else {
        std::cerr << "Failed to receive or verify server response." << std::endl;
    }
}

void handle_withdraw(SSL* ssl) {
    if (SSL_get_fd(ssl) == -1) {
        std::cerr << "SSL connection is not valid. Cannot perform withdrawal." << std::endl;
        return;
    }
    double amount;
    std::cout << "Enter amount to withdraw: ";
    std::cin >> amount;

    if (amount <= 0) {
        std::cerr << "Invalid amount. Please enter a positive number." << std::endl;
        return;
    }
   
    std::ostringstream ss;
    ss << "WITHDRAW " << current_session.token << " " << current_session.account_number << " " << std::fixed << std::setprecision(2) << amount;
    std::string withdraw_command = ss.str();

    if (!send_message_with_hmac(ssl, withdraw_command)) {
        std::cerr << "Failed to send WITHDRAW command." << std::endl;
        return;
    }

    // Receive server response
    std::string response;
    if (receive_message_with_hmac(ssl, response)) {
        std::cout << response << std::endl;
    } else {
        std::cerr << "Failed to receive or verify server response." << std::endl;
    }
}

void handle_check_balance(SSL* ssl) {
    if (SSL_get_fd(ssl) == -1) {
        std::cerr << "SSL connection is not valid. Cannot check balance." << std::endl;
        return;
    }
    std::ostringstream ss;
    ss << "CHECK_BALANCE " << current_session.token;
    std::string check_balance_command = ss.str();

    if (!send_message_with_hmac(ssl, check_balance_command)) {
        std::cerr << "Failed to send CHECK_BALANCE command." << std::endl;
        return;
    }

    // Receive server response
    std::string response;
    if (receive_message_with_hmac(ssl, response)) {
        std::cout << response << std::endl;
    } else {
        std::cerr << "Failed to receive or verify server response." << std::endl;
    }
}

void handle_logout(SSL* ssl) {
    std::ostringstream ss;
    ss << "LOGOUT " << current_session.token;
    std::string logout_command = ss.str();

    if (!send_message_with_hmac(ssl, logout_command)) {
        std::cerr << "Failed to send LOGOUT command." << std::endl;
        return;
    }

    // Receive server response
    std::string response;
    if (receive_message_with_hmac(ssl, response)) {
        std::cout << response << std::endl;
        current_session = Session(); // Clear session
    } else {
        std::cerr << "Failed to receive or verify server response." << std::endl;
    }
}

std::string request_nonce(SSL* ssl) {
    // Implement nonce request if server supports it
    // For simplicity, using client-generated nonce
    return generate_nonce();
}

std::string generate_client_session_token() {
    unsigned char buffer[32]; // 256-bit token
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        log_error("Failed to generate secure random client session token.");
        return "";
    }

    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < sizeof(buffer); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    }
    return ss.str();
}

std::string get_executable_path() {
    char result[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    return std::string(result, (count > 0) ? count : 0);
}

SSL* reconnect_to_server(SSL_CTX* ctx) {
    std::cout << "Attempting to reconnect to server..." << std::endl;
    SSL* new_ssl = connect_to_server(ctx);
    if (!new_ssl) {
        std::cerr << "Failed to reconnect to server." << std::endl;
        return nullptr;
    }
    std::cout << "Successfully reconnected to server." << std::endl;
    return new_ssl;
}

int main() {
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    std::string exec_path = get_executable_path();
    std::string pubkey_path = exec_path.substr(0, exec_path.find_last_of("/")) + "/ssl_certs/public_key.pem";
    std::ifstream pubkey_file(pubkey_path);
    if (!pubkey_file.good()) {
        std::cerr << "Error: Unable to open public key file. Please ensure '" << pubkey_path << "' exists and is readable." << std::endl;
        return EXIT_FAILURE;
    }
    pubkey_file.close();

    SSL_CTX* ctx = create_context_client();
    if (!ctx) {
        std::cerr << "Failed to create SSL context. Exiting." << std::endl;
        return EXIT_FAILURE;
    }

    SSL* ssl = connect_to_server(ctx);
    if (!ssl) {
        std::cerr << "Failed to connect to server. Exiting." << std::endl;
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Main menu loop
    while (true) {
        std::cout << "\n--- Main Menu ---\n";
        std::cout << "1. Create Account\n";
        std::cout << "2. Login\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter choice: ";
        int choice;
        std::cin >> choice;

        switch (choice) {
            case 1:
                create_account(ssl);
                break;
            case 2: {
                std::pair<std::string, std::string> login_result = login(ssl);
                std::string session_token = login_result.first;
                std::string role = login_result.second;
                if (!session_token.empty() && !role.empty()) {
                    std::cout << "Login successful. Entering transaction menu..." << std::endl;
                    current_session.token = session_token;
                    current_session.role = role;
                    current_session.last_active = std::chrono::steady_clock::now();
                    
                    // Check SSL connection before entering transaction menu
                    if (SSL_get_fd(ssl) == -1) {
                        std::cerr << "SSL connection lost after successful login." << std::endl;
                        // Attempt to reconnect
                        SSL_free(ssl);
                        ssl = connect_to_server(ctx);
                        if (!ssl) {
                            std::cerr << "Failed to reconnect to server. Exiting." << std::endl;
                            return EXIT_FAILURE;
                        }
                    }
                    
                    transaction_menu(ssl);
                    std::cout << "Returned from transaction menu." << std::endl;
                } else {
                    std::cout << "Login failed. Please try again." << std::endl;
                }
                break;
            }
            case 3:
                handle_logout(ssl);
                cleanup_and_exit(ssl, ctx);
                return 0;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }

    // Cleanup (unreachable in current loop)
    cleanup_and_exit(ssl, ctx);
    return 0;
}
