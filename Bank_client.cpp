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
#include <iomanip>
#include <regex>
#include <limits>
#include <csignal>
using namespace std;

void transaction_window(SSL *ssl);
void log_message(const string &message);
#define PUBLIC_KEY_FILE "../../certs/public_key.pem"

string session_token; 
SSL *ssl_global; 

string server_ip = "127.0.0.1";  // Default to localhost
int server_port = 8080;          // Default port

void log_error(const string &message) {
    cerr << "[ERROR] " << message << "\n";
}

bool is_valid_ip(const string &ip) {
    // Check if IP is empty or localhost
    if (ip.empty() || ip == "localhost" || ip == "127.0.0.1") {
        return true;
    }

    // Split IP address into octets
    vector<string> octets;
    stringstream ss(ip);
    string octet;
    
    while (getline(ss, octet, '.')) {
        octets.push_back(octet);
    }

    // Check if we have exactly 4 octets
    if (octets.size() != 4) {
        return false;
    }

    // Convert octets to integers
    for (const string &oct : octets) {
        // Check if octet is empty or has leading zeros (unless it's just "0")
        if (oct.empty() || (oct.length() > 1 && oct[0] == '0')) {
            return false;
        }

        // Check if octet contains only digits
        if (!all_of(oct.begin(), oct.end(), ::isdigit)) {
            return false;
        }

        try {
            int value = stoi(oct);
            if (value < 0 || value > 255) {
                return false;
            }
        } catch (...) {
            return false;
        }
    }

    return true;
} 

void get_server_details() {
    cout << "Enter server IP (default: 127.0.0.1): ";
    string input_ip;
    getline(cin, input_ip);
    
    if (!input_ip.empty()) {
        if (!is_valid_ip(input_ip)) {
            log_error("Invalid IP format. Using default: 127.0.0.1");
            server_ip = "127.0.0.1";
        } else {
            server_ip = input_ip;
        }
    } else {
        server_ip = "127.0.0.1";
    }

    cout << "Enter server port (default: 8080): ";
    string input_port;
    getline(cin, input_port);
    
    if (!input_port.empty()) {
        try {
            int port = stoi(input_port);
            if (port > 0 && port < 65536) {
                server_port = port;
            } else {
                log_error("Invalid port number (must be between 1-65535). Using default: 8080");
                server_port = 8080;
            }
        } catch (const exception&) {
            log_error("Invalid port format. Using default: 8080");
            server_port = 8080;
        }
    } else {
        server_port = 8080;
    }

    log_message("Connecting to server at " + server_ip + ":" + to_string(server_port));
}

void log_message(const string &message) {
    cout << "[INFO] " << message << "\n";
}


bool check_protocol_error(SSL *ssl, const string &response) {
    if (response.find("protocol error") != string::npos) {
        log_error("error 63");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return true;
    }
    return false;
}


string base64_encode(const string &input) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input.data(), input.size());
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    string encoded(bptr->data, bptr->length);
    BIO_free_all(b64);

    return encoded;
}


string rsa_encrypt(const string &plaintext) {
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

    vector<unsigned char> encrypted(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, (const unsigned char *)plaintext.c_str(), plaintext.size()) <= 0) {
        log_error("Encryption failed");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    return base64_encode(string(encrypted.begin(), encrypted.end()));
}


SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, "../../certs/ca_cert.pem", NULL)) {
        log_error("Failed to load CA certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load client certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "../../certs/client_cert.pem", SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load client certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "../../certs/client_key.pem", SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load client private key");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int create_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("Socket creation failed");
        return -1;
    }

    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr) <= 0) {
        log_error("Invalid address/Address not supported");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_error("Connection Failed");
        return -1;
    }

    return sock;
}

SSL *establish_ssl_connection(SSL_CTX *ctx) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("Socket creation failed");
        return nullptr;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    
    if (inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) <= 0) {
        log_error("Invalid address/Address not supported");
        close(sock);
        return nullptr;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("Connection failed to " + server_ip + ":" + to_string(server_port));
        close(sock);
        return nullptr;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        log_error("SSL connection failed");
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }

    return ssl;
}

string hash_password(const string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password.c_str(), password.size(), hash);
    
    return string((char*)hash, SHA256_DIGEST_LENGTH);
}


void derive_aes_key_iv(const string &password, unsigned char *aes_key, unsigned char *aes_iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);
    memcpy(aes_key, hash, 32);
    memcpy(aes_iv, hash + 16, 16);
}

string aes_encrypt(const string &plaintext, const unsigned char *aes_key, const unsigned char *aes_iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}
void handle_sigint(int sig) {
    log_message("Received SIGINT, shutting down client gracefully...");
    if (ssl_global) {
        SSL_shutdown(ssl_global);
        SSL_free(ssl_global);
    }
    exit(0); 
}


bool is_valid_amount_format(const string &amount_str) {
    regex amount_regex(R"(^([1-9][0-9]*|0)\.[0-9]{2}$)");
    
    if (!regex_match(amount_str, amount_regex)) {
        return false;
    }

    size_t decimal_pos = amount_str.find('.');
    return (decimal_pos != string::npos && 
            amount_str.length() - decimal_pos - 1 == 2);
}

void create_account(SSL *ssl) {
    string username, password, initial_amount_str;

    cout << "Enter username: ";
    cin.ignore(); // Clear any leftover newlines
    getline(cin, username);
    
    // Check for spaces in username
    if (username.find(' ') != string::npos) {
        log_error("ERROR 255 - Username cannot contain spaces");
        return;
    }

    cout << "Enter password: ";
    getline(cin, password);
    cout << "Enter initial amount (format: X.XX): ";
    cin >> initial_amount_str;

    if (!is_valid_amount_format(initial_amount_str)) {
        log_error("ERROR 255 - due to invalid amount format. Please use format: X.XX");
        return;
    }

    try {
        double initial_amount = stod(initial_amount_str);
        if (initial_amount < 10.00 || initial_amount > 4294967295.99) {
            log_error("ERROR 255 - due to amount out of range (10.00 to 4294967295.99)");
            return;
        }
    } catch (const exception&) {
        log_error("ERROR 255 - due to invalid amount value");
        return;
    }

    string hashed_password = hash_password(password);
    if (hashed_password.empty()) {
        log_error("ERROR 255 - hashing password failed");
        return;
    }

    unsigned char aes_key[32], aes_iv[16];
    derive_aes_key_iv(password, aes_key, aes_iv);

    string encrypted_password = aes_encrypt(hashed_password, aes_key, aes_iv);
    if (encrypted_password.empty()) {
        log_error("ERROR 255 - AES encryption failed");
        return;
    }

    string rsa_encrypted_password = rsa_encrypt(encrypted_password);
    if (rsa_encrypted_password.empty()) {
        log_error("ERROR 255 - RSA encryption failed");
        return;
    }

    string message = "CREATE_ACCOUNT " + username + " " + rsa_encrypted_password + " " + initial_amount_str;
    SSL_write(ssl, message.c_str(), message.size());

    char buffer[1024] = {0};
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        log_error("ERROR 255 - Failed to read server response");
        return;
    }
    string response(buffer, bytes_read);

    if (response.find("ERROR 255") != string::npos) {
        log_error("Server response: " + response);
        return;
    }

    size_t account_pos = response.find("\"account\":\"");
    size_t card_pos = response.find("\"card_id\":\"");
    size_t balance_pos = response.find("\"initial_balance\":");
    
    if (account_pos != string::npos && card_pos != string::npos && balance_pos != string::npos) {
        account_pos += 11; 
        size_t account_end = response.find("\"", account_pos);
        
        card_pos += 11; 
        size_t card_end = response.find("\"", card_pos);
        
        balance_pos += 17;
        size_t balance_end = response.find("}", balance_pos);
        
        string account = response.substr(account_pos, account_end - account_pos);
        string card_id = response.substr(card_pos, card_end - card_pos);
        string balance_str = response.substr(balance_pos, balance_end - balance_pos);
        
        ostringstream success_msg;
        success_msg << "{"
                    << "\"account\":\"" << account << "\","
                    << "\"card_id\":\"" << card_id << "\","
                    << "\"initial_balance\":" << balance_str
                    << "}";
        log_message("Account created successfully: " + success_msg.str());
        log_message("Please save your card ID: " + card_id);
    } else {
        log_error("Unexpected server response format: " + response);
    }

    if (response.find("ERROR 255") == string::npos) {
        session_token = "TEMP_TOKEN"; 
        log_message("Account created successfully. Please log in to start a session.");
    } else {
        log_error("Account creation failed: " + response);
    }
}

void login(SSL *ssl) {
    string username, password, card_id, account_number;

    cout << "Enter username: ";
    cin.ignore(); // Clear any leftover newlines
    getline(cin, username);
    
    // Check for spaces in username
    if (username.find(' ') != string::npos) {
        log_error("ERROR 255 - Username cannot contain spaces");
        return;
    }

    cout << "Enter password: ";
    getline(cin, password);
    cout << "Enter card ID: ";
    cin >> card_id;
    cout << "Enter account number: ";
    cin >> account_number;
    

    string hashed_password = hash_password(password);
    if (hashed_password.empty()) {
        log_error("ERROR 255 - hashing password failed");
        return;
    }

    unsigned char aes_key[32], aes_iv[16];
    derive_aes_key_iv(password, aes_key, aes_iv);

    string encrypted_password = aes_encrypt(hashed_password, aes_key, aes_iv);
    if (encrypted_password.empty()) {
        log_error("ERROR 255 - AES encryption failed");
        return;
    }

    string rsa_encrypted_password = rsa_encrypt(encrypted_password);
    if (rsa_encrypted_password.empty()) {
        log_error("ERROR 255 - RSA encryption failed");
        return;
    }

    string message = "LOGIN " + username + " " + rsa_encrypted_password + " " + card_id + " " + account_number;

    SSL_write(ssl, message.c_str(), message.size());

    char buffer[1024] = {0};
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        log_error("ERROR 255 - Failed to read server response");
        return;
    }
    string response(buffer, bytes_read);

    if (response.rfind("LOGIN_SUCCESS", 0) == 0) {
        session_token = response.substr(14);
        log_message("Login successful");
        transaction_window(ssl);
    } else {
        log_error("Login failed: " + response);
    }
}


bool check_session_expiration(SSL *ssl, const string &response) {
    if (response.find("ERROR 255 - due to invalid session token") != string::npos ||
        response.find("ERROR 255 - Session expired") != string::npos) {
        log_error("Error 63 - Session expired. Please log in again.");
        session_token.clear();
        return true;
    }
    return false;
}

void transaction_window(SSL *ssl) {
    while (true) {
        cout << "\n1. Check Balance\n2. Deposit\n3. Withdraw\n4. Logout\nEnter your choice: ";
        string input;
        cin >> input;

        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }

        if (input.length() != 1 || !isdigit(input[0])) {
            log_error("ERROR 255 - Invalid input. Please enter a number between 1-4");
            continue;
        }

        int choice = input[0] - '0';
        string message = session_token + " ";

        switch (choice) {
            case 1:
                message += "CHECK_BALANCE";
                break;
            case 2: { 
                cout << "Enter amount to deposit (format: X.XX): ";
                string amount_str;
                if (!(cin >> amount_str)) {
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    log_error("ERROR 255 - Invalid amount format");
                    continue;
                }

                if (!is_valid_amount_format(amount_str)) {
                    log_error("ERROR 255 - due to invalid amount format. Please use format: X.XX");
                    continue;
                }

                try {
                    double amt = stod(amount_str);
                    if (amt <= 0.00 || amt > 4294967295.99) {
                        log_error("ERROR 255 - due to amount out of range (0.00 to 4294967295.99)");
                        continue;
                    }
                    message += "DEPOSIT " + amount_str;
                } catch (const exception&) {
                    log_error("ERROR 255 - due to invalid amount value");
                    continue;
                }
                break;
            }
            case 3: { 
                cout << "Enter amount to withdraw (format: X.XX): ";
                string amount_str;
                if (!(cin >> amount_str)) {
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    log_error("ERROR 255 - Invalid amount format");
                    continue;
                }

                if (!is_valid_amount_format(amount_str)) {
                    log_error("ERROR 255 - due to invalid amount format. Please use format: X.XX");
                    continue;
                }

                try {
                    double amt = stod(amount_str);
                    if (amt <= 0.00 || amt > 4294967295.99) {
                        log_error("ERROR 255 - due to amount out of range (0.00 to 4294967295.99)");
                        continue;
                    }
                    message += "WITHDRAW " + amount_str;
                } catch (const exception&) {
                    log_error("ERROR 255 - due to invalid amount value");
                    continue;
                }
                break;
            }
            case 4:
                cout << "Logging out...\n";
                return;
            default:
                log_error("ERROR 255 - Invalid choice. Please enter a number between 1-4");
                continue;
        }

        SSL_write(ssl, message.c_str(), message.size());

        char buffer[1024] = {0};
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            log_error("ERROR 255 - Failed to read server response");
            return;
        }
        string response(buffer, bytes_read);

        if (check_session_expiration(ssl, response)) {
            log_message("Returning to main menu...");
            return;  // This will exit the transaction window and return to main menu
        }

        if (response.find("ERROR 255") != string::npos) {
            log_error("Server response: " + response);
            if (response.find("invalid session token") != string::npos) {
                log_message("Returning to main menu...");
                return;  // Exit to main menu on invalid session
            }
            continue;
        }

        if (response.find("\"balance\":") != string::npos) {
            size_t account_pos = response.find("\"account\":\"");
            size_t balance_pos = response.find("\"balance\":");
            
            if (account_pos != string::npos && balance_pos != string::npos) {
                account_pos += 11;
                size_t account_end = response.find("\"", account_pos);
                balance_pos += 10;
                size_t balance_end = response.find("}", balance_pos);
                
                string account = response.substr(account_pos, account_end - account_pos);
                string balance_str = response.substr(balance_pos, balance_end - balance_pos);
                
                ostringstream msg;
                msg << "{"
                    << "\"account\":\"" << account << "\","
                    << "\"balance\":" << balance_str
                    << "}";
                log_message("Check Balance Response: " + msg.str());
            }
        } else if (response.find("\"deposit\":") != string::npos) {
            size_t account_pos = response.find("\"account\":\"");
            size_t deposit_pos = response.find("\"deposit\":");
            
            if (account_pos != string::npos && deposit_pos != string::npos) {
                account_pos += 11;
                size_t account_end = response.find("\"", account_pos);
                deposit_pos += 10;
                size_t deposit_end = response.find("}", deposit_pos);
                
                string account = response.substr(account_pos, account_end - account_pos);
                string deposit_str = response.substr(deposit_pos, deposit_end - deposit_pos);
                
                ostringstream msg;
                msg << "{"
                    << "\"account\":\"" << account << "\","
                    << "\"deposit\":" << deposit_str
                    << "}";
                log_message("Deposit Response: " + msg.str());
                size_t token_pos = response.find("\"session_token\":\"");
                if (token_pos != string::npos) {
                    token_pos += 17;
                    size_t token_end = response.find("\"", token_pos);
                    session_token = response.substr(token_pos, token_end - token_pos);
                }
            }
        } else if (response.find("\"withdraw\":") != string::npos) {
            size_t account_pos = response.find("\"account\":\"");
            size_t withdraw_pos = response.find("\"withdraw\":");
            
            if (account_pos != string::npos && withdraw_pos != string::npos) {
                account_pos += 11;
                size_t account_end = response.find("\"", account_pos);
                withdraw_pos += 11;
                size_t withdraw_end = response.find("}", withdraw_pos);
                
                string account = response.substr(account_pos, account_end - account_pos);
                string withdraw_str = response.substr(withdraw_pos, withdraw_end - withdraw_pos);
                
                ostringstream msg;
                msg << "{"
                    << "\"account\":\"" << account << "\","
                    << "\"withdraw\":" << withdraw_str
                    << "}";
                log_message("Withdraw Response: " + msg.str());
            }
        } else {
            log_error("Unexpected server response format: " + response);
        }
    }
}

int main() {
    SSL_CTX *ctx = create_ssl_context();
    signal(SIGINT, handle_sigint);
    
    get_server_details();

    while (true) {
        SSL *ssl = establish_ssl_connection(ctx);
        if (!ssl) return -1;
        ssl_global = ssl;
        cout << "\n1. Create Account\n2. Login\n3. Exit\nEnter your choice: ";
        string input;
        cin >> input;
        
        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }

        if (input.length() != 1 || !isdigit(input[0])) {
            log_error("ERROR 255 - Invalid input. Please enter a number between 1-3");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            continue;
        }

        int choice = input[0] - '0';
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
                log_error("ERROR 255 - Invalid choice. Please enter a number between 1-3");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                continue;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);

        
        session_token.clear();

        
    }

    SSL_CTX_free(ctx);
    return 0;
}