// Bank_Server.cpp

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <unordered_map>
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
#include <sqlite3.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h>
#include <unordered_set>
#include <filesystem>
#include "auth.h"
using namespace std;

const int SERVER_PORT = 8443;
const int SESSION_TIMEOUT_SECONDS = 300;
const   string HMAC_KEY = "C3B1F9E2D4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8";  
const   string AES_KEY_STR = "0123456789abcdef0123456789abcdef"; 
const   string AES_IV = "abcdef9876543210";  

  mutex mtx;


struct SessionInfo {
      string account_number;
      chrono::steady_clock::time_point last_active;
};
  unordered_map<  string, SessionInfo> session_store;


enum class Role {
    USER,
    ADMIN
};


struct User {
      string name;
      string account_number;
      string hashed_pin;
      string salt;  
      string card_file; 
      string card_id;  
    Role role;
    double balance;
    int failed_attempts;
      chrono::steady_clock::time_point lockout_time;
};


  unordered_map<  string, User> user_database;


  unordered_set<  string> used_nonces;
  mutex nonce_mutex;


  string generate_hmac(const   string& message, const   string& key);
bool verify_hmac(const   string& data, const   string& key, const   string& received_hmac);
void log_error(const   string& error_message);
void log_message(const   string& message);
bool send_message_with_hmac(SSL* ssl, const   string& message);
bool receive_message_with_hmac(SSL* ssl,   string& message);
  string sha256(const   string& input);
  string generate_session_token();
bool validate_session(const   string& token);
void terminate_session(const   string& token);
double get_balance(const   string& account_number);
  string generate_account_number();
  string aes_encrypt(const   string& plaintext, const   string& key, const   string& iv);
  string aes_decrypt(const   string& ciphertext, const   string& key, const   string& iv);
  string base64_encode(const   string& input);
  string base64_decode(const   string& input);
void handle_client(SSL* ssl);
SSL_CTX* create_context();
void perform_secure_backup();
void load_secure_backup();
  string generate_nonce();
bool verify_nonce(const   string& nonce);
bool has_permission(const   string& session_token, const   string& action);
  string get_client_ip(SSL* ssl);
void check_network_status();
bool encrypt_card_file(const   string& account_number, const   string& card_data, const   string& key, const   string& iv);
  string decrypt_card_file(const   string& encrypted_card_path, const   string& key, const   string& iv);


  string generate_random_number(int length);
bool is_numeric(const   string& str);
  string rsa_decrypt(const   string& encrypted_base64);


bool verify_otp(const   string& account_number, const   string& otp);
  string rsa_decrypt(const   string& encrypted_base64);


  string get_user_role(const   string& account_number);


void handle_login(SSL* ssl, const   string& account_number, const   string& pin, const   string& card_id);


  unordered_map<  string,   string> otp_store;
  mutex otp_mutex;


  string generate_otp(const   string& account_number) {
      random_device rd;
      mt19937 gen(rd());
      uniform_int_distribution<> dis(100000, 999999);
      string otp =   to_string(dis(gen));


    {
          lock_guard<  mutex> lock(otp_mutex);
        otp_store[account_number] = otp;
    }

    return otp;
}


bool verify_otp(const   string& account_number, const   string& otp) {
      lock_guard<  mutex> lock(otp_mutex);
    auto it = otp_store.find(account_number);
    if (it != otp_store.end() && it->second == otp) {
        otp_store.erase(it); 
        return true;
    }
    return false;
}



  string generate_hmac(const   string& message, const   string& key) {
    unsigned char* digest;
    unsigned int len = EVP_MAX_MD_SIZE;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), NULL, &len);
      stringstream ss;
    for(unsigned int i = 0; i < len; ++i){
        ss <<   hex <<   setw(2) <<   setfill('0') << (int)digest[i];
    }
    return ss.str();
}


#include <openssl/evp.h>
#include <cstring>


bool constant_time_compare(const   string& a, const   string& b) {
    if (a.length() != b.length()) return false;
    unsigned char result = 0;
    for (size_t i = 0; i < a.length(); ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}


bool verify_hmac(const   string& data, const   string& key, const   string& received_hmac) {
      string calculated_hmac = generate_hmac(data, key);
    return constant_time_compare(calculated_hmac, received_hmac);
}

void log_error(const   string& error_message) {
      lock_guard<  mutex> lock(mtx);
      ofstream log_file("bank_server_error.log",   ios_base::app);
    if(log_file.is_open()) {
        auto now =   chrono::system_clock::to_time_t(  chrono::system_clock::now());
        log_file <<   ctime(&now) << ": " << error_message <<   endl;
        log_file.close();
    }
}

void log_message(const   string& message) {
      lock_guard<  mutex> lock(mtx);
      ofstream log_file("bank_server.log",   ios_base::app);
    if(log_file.is_open()) {
        auto now =   chrono::system_clock::to_time_t(  chrono::system_clock::now());
        log_file <<   ctime(&now) << ": " << message <<   endl;
        log_file.close();
    }

    
}

bool send_message_with_hmac(SSL* ssl, const   string& message) {
      string hmac = generate_hmac(message, HMAC_KEY);
      string payload = message + "|HMAC:" + hmac;
    log_message("Sending: " + payload);
    int bytes_written = SSL_write(ssl, payload.c_str(), payload.length());
    if (bytes_written <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        log_error("Failed to send message. SSL error: " +   to_string(ssl_error));
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool receive_message_with_hmac(SSL* ssl,   string& message) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        log_error("Failed to receive message. SSL error: " +   to_string(ssl_error));
        ERR_print_errors_fp(stderr);
        return false;
    }

      string received_data(buffer, bytes_read);
    log_message("Received: " + received_data);

    size_t hmac_pos = received_data.find("|HMAC:");
    if (hmac_pos ==   string::npos) {
        log_error("Received message without HMAC.");
        return false;
    }

    message = received_data.substr(0, hmac_pos);
      string received_hmac = received_data.substr(hmac_pos + 6);

    if (!verify_hmac(message, HMAC_KEY, received_hmac)) {
        log_error("HMAC verification failed.");
        return false;
    }

    log_message("Received message: " + message);
    return true;
}

  string sha256(const   string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
      stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i){
        ss <<   hex <<   setw(2) <<   setfill('0') << (int)hash[i];
    }
    return ss.str();
}

  string generate_session_token() {
    unsigned char buffer[32]; 
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        log_error("Failed to generate secure random session token.");
        return "";
    }


      stringstream ss;
    for (int i = 0; i < sizeof(buffer); ++i) {
        ss <<   hex <<   setw(2) <<   setfill('0') << (int)buffer[i];
    }
    return ss.str();
}

bool validate_session(const   string& token) {
      lock_guard<  mutex> lock(mtx);
    auto it = session_store.find(token);
    if (it == session_store.end()) {
        return false;
    }
    auto now =   chrono::steady_clock::now();
    if (  chrono::duration_cast<  chrono::seconds>(now - it->second.last_active).count() > SESSION_TIMEOUT_SECONDS) {
        session_store.erase(it);
        return false;
    }
    it->second.last_active = now; 
    return true;
}

void terminate_session(const   string& token) {
      lock_guard<  mutex> lock(mtx);
    session_store.erase(token);
}

double get_balance(const   string& account_number) {
      lock_guard<  mutex> lock(mtx);
    auto it = user_database.find(account_number);
    if (it != user_database.end()) {
        return it->second.balance;
    }
    return -1;  
}

  string generate_account_number() {
    return generate_random_number(10);
}


  string generate_random_number(int length) {
      random_device rd;
      mt19937 gen(rd());
      uniform_int_distribution<> dis(0,9);
      string number;
    for(int i = 0; i < length; ++i){
        number +=   to_string(dis(gen));
    }
    return number;
}

  string aes_encrypt(const   string& plaintext, const   string& key, const   string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create EVP_CIPHER_CTX for encryption.");
        return "";
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                        reinterpret_cast<const unsigned char*>(key.c_str()), 
                        reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        log_error("Failed to initialize AES encryption.");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
      vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                        reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                        plaintext.length()) != 1) {
        log_error("Failed during AES encryption update.");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        log_error("Failed to finalize AES encryption.");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return   string(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
}

  string aes_decrypt(const   string& ciphertext, const   string& key, const   string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("Failed to create EVP_CIPHER_CTX for decryption.");
        return "";
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                        reinterpret_cast<const unsigned char*>(key.c_str()), 
                        reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        log_error("Failed to initialize AES decryption.");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
      vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                        reinterpret_cast<const unsigned char*>(ciphertext.c_str()), 
                        ciphertext.length()) != 1) {
        log_error("Failed during AES decryption update.");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        log_error("Failed to finalize AES decryption.");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return   string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

  string base64_encode(const   string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

      string output(bufferPtr->data, bufferPtr->length);
    BUF_MEM_free(bufferPtr);
    return output;
}

  string base64_decode(const   string& input) {
    BIO *bio, *b64;
    char *buffer = new char[input.length()];
    memset(buffer, 0, input.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_length = BIO_read(bio, buffer, input.length());
    BIO_free_all(bio);

      string output(buffer, decoded_length);
    delete[] buffer;
    return output;
}

SSL_CTX* create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error("Unable to create SSL context.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load server certificate.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        log_error("Failed to load server private key.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    if (!SSL_CTX_check_private_key(ctx)) {
        log_error("Private key does not match the certificate public key.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void handle_client(SSL* ssl) {

    if (SSL_accept(ssl) <= 0) {
        log_error("SSL handshake failed.");
        ERR_print_errors_fp(stderr);
        return;
    }

    log_message("SSL connection established successfully.");

      string client_ip = get_client_ip(ssl);
    log_message("New client connected from IP: " + client_ip);

      string account_number;

    while (true) {
          string message;
        if (!receive_message_with_hmac(ssl, message)) {
            log_error("Failed to receive message from client: " + client_ip);
            break;
        }

          istringstream iss(message);
          string command;
        iss >> command;

        if (command == "CREATE_ACCOUNT") {
              string name, pin, card_data;
            iss >> name >> pin;

            iss >> card_data;


              string hashed_pin = sha256(pin);


              string new_account = generate_account_number();


              string encrypted_card = aes_encrypt(card_data, AES_KEY_STR, AES_IV);
              string card_file_path = "cards/" + new_account + ".enc";
              ofstream card_file(card_file_path,   ios::binary);
            if (card_file.is_open()) {
                card_file << encrypted_card;
                card_file.close();
            } else {
                send_message_with_hmac(ssl, "FAILURE: Unable to store card data.");
                log_error("Failed to store card data for account: " + new_account);
                continue;
            }


            User new_user;
            new_user.name = name;
            new_user.account_number = new_account;
            new_user.hashed_pin = hashed_pin;
            new_user.card_file = card_file_path;
            new_user.role = Role::USER;
            new_user.balance = 0.0;
            new_user.failed_attempts = 0;

            {
                  lock_guard<  mutex> lock(mtx);
                user_database[new_account] = new_user;
            }


              string response = "SUCCESS: Account created. Account Number: " + new_account;
            send_message_with_hmac(ssl, response);
            log_message("Account created for user: " + name + ", Account Number: " + new_account);
            perform_secure_backup();
        }
        else if (command == "LOGIN") {
              string account_number, encrypted_pin, card_id, nonce;
            iss >> account_number >> encrypted_pin >> card_id >> nonce;

            log_message("Received LOGIN command. Account: " + account_number + ", Card ID: " + card_id);

            if (!verify_nonce(nonce)) {
                send_message_with_hmac(ssl, "FAILURE: Invalid nonce.");
                log_error("Login attempt with invalid nonce for account: " + account_number);
                continue;
            }

              string decrypted_pin = rsa_decrypt(encrypted_pin);
            if (decrypted_pin.empty()) {
                send_message_with_hmac(ssl, "FAILURE: Error decrypting PIN.");
                log_error("Failed to decrypt PIN for account: " + account_number);
                continue;
            }

            handle_login(ssl, account_number, decrypted_pin, card_id);
        }
        else if (command == "DEPOSIT") {
              string token;
            double amount;
            iss >> token >> amount;

            log_message("Deposit request: Token - " + token + ", Amount - " +   to_string(amount));

            if (!validate_session(token)) {
                send_message_with_hmac(ssl, "FAILURE: Invalid or expired session.");
                log_error("Invalid session token during deposit.");
                continue;
            }


              string account_number;
            {
                  lock_guard<  mutex> lock(mtx);
                auto session_it = session_store.find(token);
                if (session_it != session_store.end()) {
                    account_number = session_it->second.account_number;
                }
            }

            if (account_number.empty()) {
                send_message_with_hmac(ssl, "FAILURE: Session mapping error.");
                log_error("Session token does not map to an account.");
                continue;
            }

            {
                  lock_guard<  mutex> lock(mtx);
                auto it = user_database.find(account_number);
                if (it != user_database.end()) {
                    it->second.balance += amount;
                      string response = "SUCCESS: New balance is " +   to_string(it->second.balance);
                    send_message_with_hmac(ssl, response);
                    log_message("Deposit successful for account: " + account_number + ", New balance: " +   to_string(it->second.balance));
                    perform_secure_backup();
                }
                else {
                    send_message_with_hmac(ssl, "FAILURE: Account not found.");
                    log_error("Deposit attempt for non-existent account: " + account_number);
                }
            }
        }
        else if (command == "WITHDRAW") {
              string token;
            double amount;
            iss >> token >> amount;

            log_message("Withdrawal request: Token - " + token + ", Amount - " +   to_string(amount));

            if (!validate_session(token)) {
                send_message_with_hmac(ssl, "FAILURE: Invalid or expired session.");
                log_error("Invalid session token during withdrawal.");
                continue;
            }


              string account_number;
            {
                  lock_guard<  mutex> lock(mtx);
                auto session_it = session_store.find(token);
                if (session_it != session_store.end()) {
                    account_number = session_it->second.account_number;
                }
            }

            if (account_number.empty()) {
                send_message_with_hmac(ssl, "FAILURE: Session mapping error.");
                log_error("Session token does not map to an account.");
                continue;
            }

            {
                  lock_guard<  mutex> lock(mtx);
                auto it = user_database.find(account_number);
                if (it != user_database.end()) {
                    if (it->second.balance >= amount) {
                        it->second.balance -= amount;
                          string response = "SUCCESS: New balance is " +   to_string(it->second.balance);
                        send_message_with_hmac(ssl, response);
                        log_message("Withdrawal successful for account: " + account_number + ", New balance: " +   to_string(it->second.balance));
                        perform_secure_backup();
                    }
                    else {
                        send_message_with_hmac(ssl, "FAILURE: Insufficient funds.");
                        log_error("Insufficient funds for withdrawal in account: " + account_number);
                    }
                }
                else {
                    send_message_with_hmac(ssl, "FAILURE: Account not found.");
                    log_error("Withdrawal attempt for non-existent account: " + account_number);
                }
            }
        }
        else if (command == "CHECK_BALANCE") {
              string token;
            iss >> token;

            log_message("Balance check request: Token - " + token);

            if (!validate_session(token)) {
                send_message_with_hmac(ssl, "FAILURE: Invalid or expired session.");
                log_error("Invalid session token during balance check.");
                continue;
            }


              string account_number;
            {
                  lock_guard<  mutex> lock(mtx);
                auto session_it = session_store.find(token);
                if (session_it != session_store.end()) {
                    account_number = session_it->second.account_number;
                }
            }

            if (account_number.empty()) {
                send_message_with_hmac(ssl, "FAILURE: Session mapping error.");
                log_error("Session token does not map to an account.");
                continue;
            }

            {
                  lock_guard<  mutex> lock(mtx);
                auto it = user_database.find(account_number);
                if (it != user_database.end()) {
                      ostringstream ss;
                    ss << "SUCCESS: Current balance is " << it->second.balance;
                    send_message_with_hmac(ssl, ss.str());
                    log_message("Balance check successful for account: " + account_number + ", Balance: " +   to_string(it->second.balance));
                }
                else {
                    send_message_with_hmac(ssl, "FAILURE: Account not found.");
                    log_error("Balance check for non-existent account: " + account_number);
                }
            }
        }
        else if (command == "LOGOUT") {
              string token;
            iss >> token;

            log_message("Logout request: Token - " + token);

            if (validate_session(token)) {
                terminate_session(token);
                send_message_with_hmac(ssl, "SUCCESS: Logged out successfully.");
                log_message("User logged out: Token - " + token);
            }
            else {
                send_message_with_hmac(ssl, "FAILURE: Invalid session.");
                log_error("Invalid session token during logout.");
            }
        }
        else {
            send_message_with_hmac(ssl, "FAILURE: Unknown command.");
            log_error("Received unknown command: " + command);
        }
    }
}

void perform_secure_backup() {
      lock_guard<  mutex> lock(mtx);
      stringstream ss;
    for (const auto& pair : user_database) {
        const User& user = pair.second;
        ss << user.name << "," << user.account_number << "," << user.hashed_pin << ","
           << user.card_file << "," << static_cast<int>(user.role) << "," << user.balance << ","
           << user.failed_attempts << "," <<   chrono::duration_cast<  chrono::seconds>(
           user.lockout_time.time_since_epoch()).count() << "\n";
    }
      string plaintext = ss.str();

      string encrypted_data = aes_encrypt(plaintext, AES_KEY_STR, AES_IV);
      string encoded_data = base64_encode(encrypted_data);

      ofstream backup_file("secure_backup.dat",   ios::out |   ios::binary);
    if (backup_file.is_open()) {
        backup_file << encoded_data;
        backup_file.close();
        log_message("Secure backup performed successfully.");
    }
    else {
        log_error("Failed to open backup file for writing.");
    }
}


void load_secure_backup() {
      ifstream backup_file("secure_backup.dat",   ios::in |   ios::binary);
    if (!backup_file.is_open()) {
        log_message("No existing backup file found. Starting with an empty database.");
        return;
    }

      string encoded_data((  istreambuf_iterator<char>(backup_file)),
                                  istreambuf_iterator<char>());
    backup_file.close();

      string encrypted_data = base64_decode(encoded_data);
      string decrypted_data = aes_decrypt(encrypted_data, AES_KEY_STR, AES_IV);

    if(decrypted_data.empty()){
        log_error("Decrypted backup data is empty.");
        return;
    }

      istringstream iss(decrypted_data);
      string line;
    int user_count = 0;
    while (  getline(iss, line)) {
        if(line.empty()) continue; 

          istringstream line_stream(line);
          string name, account_number, hashed_pin, card_file, role_str, balance_str, attempts_str, lockout_str;

          getline(line_stream, name, ',');
          getline(line_stream, account_number, ',');
          getline(line_stream, hashed_pin, ',');
          getline(line_stream, card_file, ',');
          getline(line_stream, role_str, ',');
          getline(line_stream, balance_str, ',');
          getline(line_stream, attempts_str, ',');
          getline(line_stream, lockout_str, '\n');

        if(name.empty() || account_number.empty() || hashed_pin.empty() || card_file.empty() ||
           role_str.empty() || balance_str.empty() || attempts_str.empty() || lockout_str.empty()){
               log_error("Incomplete user data found in backup for account: " + account_number);
               continue; 
        }

        User user;
        user.name = name;
        user.account_number = account_number;
        user.hashed_pin = hashed_pin;
        user.card_file = card_file;

        try {
            int role_int =   stoi(role_str);
            if(role_int < static_cast<int>(Role::USER) || role_int > static_cast<int>(Role::ADMIN)){
                log_error("Invalid role value for account: " + account_number);
                continue;
            }
            user.role = static_cast<Role>(role_int);
        }
        catch (const   invalid_argument& e) {
            log_error("Invalid role string for account: " + account_number + ". Error: " + e.what());
            continue;
        }
        catch (const   out_of_range& e) {
            log_error("Role value out of range for account: " + account_number + ". Error: " + e.what());
            continue;
        }


        try {
            user.balance =   stod(balance_str);
        }
        catch (const   invalid_argument& e) {
            log_error("Invalid balance string for account: " + account_number + ". Error: " + e.what());
            continue;
        }
        catch (const   out_of_range& e) {
            log_error("Balance value out of range for account: " + account_number + ". Error: " + e.what());
            continue;
        }


        try {
            user.failed_attempts =   stoi(attempts_str);
        }
        catch (const   invalid_argument& e) {
            log_error("Invalid failed_attempts string for account: " + account_number + ". Error: " + e.what());
            continue;
        }
        catch (const   out_of_range& e) {
            log_error("failed_attempts value out of range for account: " + account_number + ". Error: " + e.what());
            continue;
        }


        try {
            long long lockout_seconds =   stoll(lockout_str);
            user.lockout_time =   chrono::steady_clock::time_point() +   chrono::seconds(lockout_seconds);
        }
        catch (const   invalid_argument& e) {
            log_error("Invalid lockout_time string for account: " + account_number + ". Error: " + e.what());
            continue;
        }
        catch (const   out_of_range& e) {
            log_error("lockout_time value out of range for account: " + account_number + ". Error: " + e.what());
            continue;
        }


        user_database[account_number] = user;
        user_count++;
    }

    log_message("Secure backup loaded successfully. User count: " +   to_string(user_count));
}


  string generate_nonce() {
      string nonce = generate_random_number(32);
    {
          lock_guard<  mutex> lock(nonce_mutex);
        used_nonces.insert(nonce);
    }
    return nonce;
}


bool verify_nonce(const   string& nonce) {
      lock_guard<  mutex> lock(nonce_mutex);
    if (used_nonces.find(nonce) != used_nonces.end()) {
        used_nonces.erase(nonce); 
        return true;
    }
    return false;
}

bool has_permission(const   string& session_token, const   string& action) {
      lock_guard<  mutex> lock(mtx);
    auto it = session_store.find(session_token);
    if (it == session_store.end()) {
        log_error("Session token not found: " + session_token);
        return false;
    }


      string account_number = it->second.account_number;

    auto user_it = user_database.find(account_number);
    if (user_it == user_database.end()) {
        log_error("User not found for account: " + account_number);
        return false;
    }

    if (action == "DELETE_ACCOUNT" && user_it->second.role != Role::ADMIN) {
        log_error("Permission denied for action: " + action + " for account: " + account_number);
        return false;
    }

    

    return true;
}

  string get_client_ip(SSL* ssl) {
    int fd = SSL_get_fd(ssl);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(fd, (struct sockaddr*)&addr, &addr_len);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
    return   string(ip);
}

bool encrypt_card_file(const   string& account_number, const   string& card_data, const   string& key, const   string& iv) {
      string encrypted = aes_encrypt(card_data, key, iv);
      string file_path = "cards/" + account_number + ".enc";
      ofstream ofs(file_path,   ios::binary);
    if (!ofs.is_open()) {
        log_error("Failed to open card file for encryption: " + file_path);
        return false;
    }
    ofs << encrypted;
    ofs.close();
    return true;
}

  string decrypt_card_file(const   string& encrypted_card_path, const   string& key, const   string& iv) {
      ifstream ifs(encrypted_card_path,   ios::binary);
    if (!ifs.is_open()) {
        log_error("Failed to open encrypted card file for decryption: " + encrypted_card_path);
        return "";
    }
      stringstream buffer;
    buffer << ifs.rdbuf();
      string encrypted_data = buffer.str();
    ifs.close();
    return aes_decrypt(encrypted_data, key, iv);
}

void handle_client_thread(int client_socket, SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    if (SSL_accept(ssl) <= 0) {
        log_error("TLS handshake failed with client.");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        return;
    }

    handle_client(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    log_message("Client connection closed.");
}

bool is_numeric(const   string& str) {
    return !str.empty() &&   all_of(str.begin(), str.end(), ::isdigit);
}


void handle_create_account(SSL* ssl, const   string& name, const   string& encrypted_pin_hex, const   string& card_data, const   string& nonce) {
      string decrypted_pin = rsa_decrypt(encrypted_pin_hex);
    if (decrypted_pin.empty()) {
        send_message_with_hmac(ssl, "FAILURE: Error decrypting PIN.");
        return;
    }
      string salt = generateSalt();
      string hashed_pin = hashPassword(decrypted_pin, salt);
    if (hashed_pin.empty()) {
        send_message_with_hmac(ssl, "FAILURE: Error hashing PIN.");
        return;
    }

      string new_account = generate_account_number();

    
    log_message("Received card data: " + card_data);


    User new_user;
    new_user.name = name;
    new_user.account_number = new_account;
    new_user.hashed_pin = hashed_pin;
    new_user.salt = salt;
    new_user.card_id = card_data;


      string cards_dir = "cards";
    if (!  filesystem::exists(cards_dir)) {
        try {
              filesystem::create_directory(cards_dir);
            log_message("Created cards directory: " + cards_dir);
        } catch (const   filesystem::filesystem_error& e) {
            log_error("Failed to create cards directory: " +   string(e.what()));
            send_message_with_hmac(ssl, "FAILURE: Unable to create cards directory.");
            return;
        }
    }

      string card_file_path = cards_dir + "/" + new_account + ".card";
      ofstream card_file(card_file_path);
    if (card_file.is_open()) {
        card_file << card_data;
        card_file.close();
        if (card_file.fail()) {
            log_error("Failed to write card data to file: " + card_file_path + ". Error: " +   strerror(errno));
            send_message_with_hmac(ssl, "FAILURE: Unable to store card data. Error: " +   string(  strerror(errno)));
            return;
        }
        log_message("Successfully wrote card data to file: " + card_file_path);
    } else {
        log_error("Failed to open card file for writing: " + card_file_path + ". Error: " +   strerror(errno));
        send_message_with_hmac(ssl, "FAILURE: Unable to store card data. Error: " +   string(  strerror(errno)));
        return;
    }

    new_user.card_file = card_file_path;
    new_user.role = Role::USER;
    new_user.balance = 0.0;
    new_user.failed_attempts = 0;

    {
          lock_guard<  mutex> lock(mtx);
        user_database[new_account] = new_user;
    }


      ostringstream response_ss;
    response_ss << "SUCCESS: Account created. Account Number: " << new_account;
      string response = response_ss.str();
    send_message_with_hmac(ssl, response);
    log_message("Account created for user: " + name + ", Account Number: " + new_account);
    perform_secure_backup();
}


void handle_login(SSL* ssl, const   string& account_number, const   string& pin, const   string& card_id) {
    log_message("Login attempt for account: " + account_number);
    
      lock_guard<  mutex> lock(mtx);
    auto it = user_database.find(account_number);
    if (it == user_database.end()) {
        send_message_with_hmac(ssl, "FAILURE: Invalid account number.");
        log_error("Login attempt with invalid account number: " + account_number);
        return;
    }

    User& user = it->second;
    log_message("User found. Verifying card ID and PIN.");


    if (user.card_id != card_id) {
        send_message_with_hmac(ssl, "FAILURE: Invalid card ID.");
        log_error("Login attempt with invalid card ID for account: " + account_number);
        return;
    }


      string hashed_pin = hashPassword(pin, user.salt);
    if (hashed_pin != user.hashed_pin) {
        user.failed_attempts++;
        if (user.failed_attempts >= 3) {
            user.lockout_time =   chrono::steady_clock::now() +   chrono::minutes(15);
            send_message_with_hmac(ssl, "FAILURE: Account locked. Try again after 15 minutes.");
            log_error("Account locked due to multiple failed attempts: " + account_number);
        } else {
            send_message_with_hmac(ssl, "FAILURE: Invalid PIN.");
            log_error("Login attempt with invalid PIN for account: " + account_number);
        }
        return;
    }

    log_message("PIN verified successfully. Generating OTP.");


    user.failed_attempts = 0;


      string otp = generateOTP();
      string otp_message = "OTP:" + otp;
    send_message_with_hmac(ssl, otp_message);
    log_message("OTP sent to client: " + otp);


      string client_otp_command;
    if (!receive_message_with_hmac(ssl, client_otp_command)) {
        send_message_with_hmac(ssl, "FAILURE: Failed to receive OTP.");
        log_error("Failed to receive OTP from account: " + account_number);
        return;
    }
    log_message("Received OTP command from client: " + client_otp_command);


      istringstream iss(client_otp_command);
      string command, received_account, received_otp, nonce;
    iss >> command >> received_account >> received_otp >> nonce;

    if (command != "OTP" || received_account != account_number) {
        send_message_with_hmac(ssl, "FAILURE: Invalid OTP command.");
        log_error("Invalid OTP command from account: " + account_number);
        return;
    }


    if (received_otp != otp) {
        send_message_with_hmac(ssl, "FAILURE: Invalid OTP.");
        log_error("Invalid OTP attempt for account: " + account_number);
        return;
    }

    log_message("OTP verified successfully. Generating session token.");


      string session_token = generate_session_token();
      string role = (user.role == Role::ADMIN) ? "ADMIN" : "USER";
      ostringstream ss;
    ss << "SUCCESS: Logged in successfully. Session Token: " << session_token << " Role: " << role;
    send_message_with_hmac(ssl, ss.str());


    SessionInfo session_info;
    session_info.account_number = account_number;
    session_info.last_active =   chrono::steady_clock::now();
    session_store[session_token] = session_info;

    log_message("User logged in successfully: " + account_number);
}

  string get_user_role(const   string& account_number) {
      lock_guard<  mutex> lock(mtx);
    auto it = user_database.find(account_number);
    if (it != user_database.end()) {
        return (it->second.role == Role::ADMIN) ? "ADMIN" : "USER";
    }
    return "UNKNOWN";
}

  string rsa_decrypt(const   string& encrypted_data) {

    FILE* key_file = fopen("ssl_certs/private_key.pem", "rb");
    if (!key_file) {
        log_error("Failed to open private key file.");
        return "";
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
    fclose(key_file);

    if (!pkey) {
        log_error("Failed to read private key.");
        return "";
    }


    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        log_error("Failed to create EVP_PKEY_CTX.");
        EVP_PKEY_free(pkey);
        return "";
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        log_error("Failed to initialize decryption operation.");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        log_error("Failed to set RSA padding.");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }


    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen,
                         reinterpret_cast<const unsigned char*>(encrypted_data.c_str()),
                         encrypted_data.length()) <= 0) {
        log_error("Failed to determine decryption buffer length.");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }


      vector<unsigned char> decrypted(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen,
                         reinterpret_cast<const unsigned char*>(encrypted_data.c_str()),
                         encrypted_data.length()) <= 0) {
        log_error("Failed to decrypt data.");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }


    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return   string(reinterpret_cast<char*>(decrypted.data()), outlen);
}

int main() {

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_add_all_algorithms_conf();

    SSL_CTX* ctx = create_context();

    
    load_secure_backup();

    
      string cards_dir = "cards";
    if (!  filesystem::exists(cards_dir)) {
        try {
              filesystem::create_directory(cards_dir);
            log_message("Created cards directory: " + cards_dir);
        } catch (const   filesystem::filesystem_error& e) {
            log_error("Failed to create cards directory: " +   string(e.what()));
            exit(EXIT_FAILURE);
        }
    }

   
    if (access(cards_dir.c_str(), W_OK) != 0) {
        log_error("No write permissions in cards directory. Error: " +   string(  strerror(errno)));
        exit(EXIT_FAILURE);
    }


    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_error("Socket creation failed.");
        perror("socket");
        exit(EXIT_FAILURE);
    }


    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        log_error("setsockopt failed.");
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_error("Bind failed.");
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        log_error("Listen failed.");
        perror("listen");
        exit(EXIT_FAILURE);
    }

    log_message("Bank server is running and listening on port " +   to_string(SERVER_PORT) + ".");

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            log_error("Failed to accept client connection.");
            perror("accept");
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);


          thread client_thread(handle_client, ssl);
        client_thread.detach();
    }


    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
