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
using namespace std;


const int SERVER_PORT = 8443;
const char* SERVER_IP = "127.0.0.1";
const int SESSION_TIMEOUT_SECONDS = 300;
const  string HMAC_KEY = "C3B1F9E2D4A6B8C0D2E4F6A8B0C2D4E6F8A0B2C4D6E8F0A2B4C6D8E0F2A4B6C8"; 
const  string AES_KEY_STR = "0123456789abcdef0123456789abcdef"; 
const  string AES_IV = "abcdef9876543210"; 


struct Session {
     string token;
     string account_number;
     chrono::steady_clock::time_point last_active;
     string role;
};
Session current_session;

 string generate_hmac(const  string& message, const  string& key);
bool verify_hmac(const  string& data, const  string& key, const  string& received_hmac);
void log_error(const  string& error_message);
void log_message(const  string& message);
 string sha256(const  string& input);
 string generate_session_token();
bool is_session_active();
void update_session_activity();
 string generate_nonce();
bool send_message_with_hmac(SSL* ssl, const  string& message);
bool receive_message_with_hmac(SSL* ssl,  string& message);
 string base64_encode(const  string& input);
 string base64_decode(const  string& input);
 string rsa_encrypt(const  string& plaintext);
SSL_CTX* create_context_client();
SSL* connect_to_server(SSL_CTX* ctx);
void cleanup_and_exit(SSL* ssl, SSL_CTX* ctx);
 string sanitize_input(const  string& input);
void create_account(SSL* ssl);
 pair< string,  string> login(SSL* ssl);
void transaction_menu(SSL* ssl);
void handle_deposit(SSL* ssl);
void handle_withdraw(SSL* ssl);
void handle_check_balance(SSL* ssl);
void handle_logout(SSL* ssl);
 string request_nonce(SSL* ssl);
bool compare_certificates(X509* cert1, X509* cert2);
X509* load_pinned_cert(const  string& pinned_cert_path);
 string generate_client_session_token();
 string generate_card_data();
 string get_executable_path();
SSL* reconnect_to_server(SSL_CTX* ctx);


 mutex mtx;


bool is_numeric(const  string& str) {
    return !str.empty() &&  all_of(str.begin(), str.end(), ::isdigit);
}



 string generate_hmac(const  string& message, const  string& key) {
    unsigned char* digest;
    unsigned int len = EVP_MAX_MD_SIZE;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                 reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), NULL, &len);
     stringstream ss;
    for(unsigned int i = 0; i < len; ++i){
        ss <<  hex <<  setw(2) <<  setfill('0') << (int)digest[i];
    }
    return ss.str();
}

bool verify_hmac(const  string& data, const  string& key, const  string& received_hmac) {
     string calculated_hmac = generate_hmac(data, key);
    return calculated_hmac == received_hmac;
}

void log_error(const  string& error_message) {
     lock_guard< mutex> lock(mtx); 
     ofstream log_file("atm_client_error.log",  ios_base::app);
    if(log_file.is_open()) {
        auto now =  chrono::system_clock::to_time_t( chrono::system_clock::now());
        log_file <<  ctime(&now) << ": " << error_message <<  endl;
        log_file.close();
    }
}

void log_message(const  string& message) {
     lock_guard< mutex> lock(mtx);
     ofstream log_file("atm_client.log",  ios_base::app);
    if(log_file.is_open()) {
        auto now =  chrono::system_clock::to_time_t( chrono::system_clock::now());
        log_file <<  ctime(&now) << ": " << message <<  endl;
        log_file.close();
    }
    
}

 string sha256(const  string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
     stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss <<  hex <<  setw(2) <<  setfill('0') << (int)hash[i];
    }
    return ss.str();
}

 string generate_session_token() {
    unsigned char random_data[32];
    if (RAND_bytes(random_data, sizeof(random_data)) != 1) {
        log_error("Failed to generate random data for session token.");
        return "";
    }
    return base64_encode( string(reinterpret_cast<char*>(random_data), sizeof(random_data)));
}

bool is_session_active() {
    if (current_session.token.empty()) {
        return false;
    }
    auto now =  chrono::steady_clock::now();
    auto elapsed =  chrono::duration_cast< chrono::seconds>(now - current_session.last_active).count();
    return elapsed < SESSION_TIMEOUT_SECONDS;
}

void update_session_activity() {
    current_session.last_active =  chrono::steady_clock::now();
}

 string generate_nonce() {

     string nonce;
     string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
     random_device rd;
     mt19937 gen(rd());
     uniform_int_distribution<> dis(0, chars.size() - 1);
    for(int i = 0; i < 32; ++i){
        nonce += chars[dis(gen)];
    }
    return nonce;
}

bool send_message_with_hmac(SSL* ssl, const  string& message) {
     string hmac = generate_hmac(message, HMAC_KEY);
     string payload = message + "|HMAC:" + hmac;
    log_message("Sending: " + payload);
    int bytes_written = SSL_write(ssl, payload.c_str(), payload.length());
    if (bytes_written <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        log_error("Failed to send message. SSL error: " +  to_string(ssl_error));
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool receive_message_with_hmac(SSL* ssl,  string& message) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        log_error("Failed to receive message. SSL error: " +  to_string(ssl_error));
        ERR_print_errors_fp(stderr);
        return false;
    }

     string received_data(buffer, bytes_read);
    log_message("Received: " + received_data);

    size_t hmac_pos = received_data.find("|HMAC:");
    if (hmac_pos ==  string::npos) {
        log_error("Received message without HMAC.");
        return false;
    }

    message = received_data.substr(0, hmac_pos);
     string received_hmac = received_data.substr(hmac_pos + 6);

    if (!verify_hmac(message, HMAC_KEY, received_hmac)) {
        log_error("HMAC verification failed.");
        return false;
    }

    log_message("Received verified message: " + message);
    return true;
}

 string base64_encode(const  string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
     string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

 string base64_decode(const  string& input) {
    BIO *bio, *b64;
    char *buffer = new char[input.length()];
    memset(buffer, 0, input.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_size = BIO_read(bio, buffer, input.length());
    BIO_free_all(bio);

     string output(buffer, decoded_size);
    delete[] buffer;
    return output;
}

 string rsa_encrypt(const  string& plaintext) {
     string pubkey_path = "ssl_certs/public_key.pem";
    FILE* pubkey_file = fopen(pubkey_path.c_str(), "rb");
    if (!pubkey_file) {
        log_error("Failed to open public key file: " + pubkey_path);
         cerr << "Error: " << strerror(errno) <<  endl;
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


    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        log_error("Failed to set RSA padding.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }


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


     vector<unsigned char> ciphertext(outlen);
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


    return base64_encode( string(reinterpret_cast<char*>(ciphertext.data()), outlen));
}

SSL_CTX* create_context_client() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error("Unable to create SSL context.");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }


    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);


    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        log_error("Failed to load default CA certificates.");
        ERR_print_errors_fp(stderr);
    }

    return ctx;
}


bool compare_certificates(X509* cert1, X509* cert2) {
    if (!cert1 || !cert2) return false;
    return X509_cmp(cert1, cert2) == 0;
}


X509* load_pinned_cert(const  string& pinned_cert_path) {
    FILE* fp = fopen(pinned_cert_path.c_str(), "r");
    if (!fp) {
        log_error("Failed to open pinned certificate file: " + pinned_cert_path);
        return nullptr;
    }
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return cert;
}


SSL* connect_to_server(SSL_CTX* ctx) {
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("Unable to create socket.");
        return nullptr;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);


    if(inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)  {
        log_error("Invalid address/ Address not supported.");
        close(sock);
        return nullptr;
    }


    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection Failed.");
        close(sock);
        return nullptr;
    }


    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);


    if (SSL_connect(ssl) <= 0) {
        log_error("SSL connection failed.");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }

    log_message("Connected to the server with " +  string(SSL_get_cipher(ssl)) + " encryption.");
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

 string sanitize_input(const  string& input) {
     string sanitized;
    for (char c : input) {
        if ( isalnum(c) || c == '_' || c == '-' || c == '.') {
            sanitized += c;
        }
    }
    return sanitized;
}

 string generate_card_data() {

     string card_number;
     random_device rd;
     mt19937 gen(rd());
     uniform_int_distribution<> dis(0, 9);
    
    for (int i = 0; i < 16; ++i) {
        card_number +=  to_string(dis(gen));
    }
    
    return card_number;
}

void create_account(SSL* ssl) {
     string name, pin;
    
     cout << "Enter your name: ";
     cin.ignore(); 
     getline( cin, name);
    name = sanitize_input(name);

   
    while (true) {
         cout << "Enter PIN (4-6 digits): ";
         cin >> pin;
        pin = sanitize_input(pin);

        if (pin.length() < 4 || pin.length() > 6 || !is_numeric(pin)) {
             cerr << "Invalid PIN. Please enter a 4-6 digit numeric PIN." <<  endl;
        } else {
            break;
        }
    }


     string card_data = generate_card_data();
     cout << "Generated card number: " << card_data <<  endl;


     string nonce = generate_nonce();


     string encrypted_pin = rsa_encrypt(pin);
    if (encrypted_pin.empty()) {
         cerr << "Failed to encrypt PIN. Please check if the public key file exists and is readable." <<  endl;
        return;
    }

     ostringstream ss;
    ss << "CREATE_ACCOUNT " << name << " " << base64_encode(encrypted_pin) << " " << card_data << " " << nonce;
     string create_command = ss.str();

    if (!send_message_with_hmac(ssl, create_command)) {
         cerr << "Failed to send CREATE_ACCOUNT command." <<  endl;
        return;
    }


     string response;
    if (receive_message_with_hmac(ssl, response)) {
        //  cout << response <<  endl;
        if (response.find("SUCCESS") !=  string::npos) {
            size_t account_number_pos = response.find("Account Number:");
            if (account_number_pos !=  string::npos) {
                 string account_number = response.substr(account_number_pos + 16);
                 cout << "Your account number is: " << account_number <<  endl;
                 cout << "Please remember your account number and card number for login." <<  endl;
            }
        } else if (response.find("FAILURE") !=  string::npos) {
             cerr << "Account creation failed. Server response: " << response <<  endl;
             cerr << "This might be due to a server-side issue. Please try again later or contact support." <<  endl;
        }
    } else {
         cerr << "Failed to receive or verify server response." <<  endl;
    }
}

 pair< string,  string> login(SSL* ssl) {
     string account_number, pin, card_data;

     cout << "Enter account number: ";
     cin >> account_number;
    account_number = sanitize_input(account_number);

     cout << "Enter PIN: ";
     cin >> pin;
    pin = sanitize_input(pin);

     cout << "Enter card number: ";
     cin >> card_data;
    card_data = sanitize_input(card_data);


     string nonce = generate_nonce();


     string encrypted_pin = rsa_encrypt(pin);
    if (encrypted_pin.empty()) {
         cerr << "Failed to encrypt PIN. Please check if the public key file exists and is readable." <<  endl;
        return {"", ""};
    }


     ostringstream ss;
    ss << "LOGIN " << account_number << " " << base64_encode(encrypted_pin) << " " << card_data << " " << nonce;
     string login_command = ss.str();

    if (!send_message_with_hmac(ssl, login_command)) {
         cerr << "Failed to send LOGIN command." <<  endl;
        return {"", ""};
    }


    if (SSL_get_fd(ssl) == -1) {
         cerr << "SSL connection lost after sending LOGIN command." <<  endl;
        return {"", ""};
    }


     string response;
    if (receive_message_with_hmac(ssl, response)) {
        //  cout << "Received response: " << response <<  endl;  

        if (response.find("OTP:") !=  string::npos) {
            
            size_t otp_pos = response.find("OTP:");
             string otp = response.substr(otp_pos + 4);
            otp = sanitize_input(otp);  
            //  cout << "Received OTP: " << otp <<  endl; 

            
             string user_otp;
             cout << "Enter OTP received on your device: ";
             cin >> user_otp;
            user_otp = sanitize_input(user_otp);

            if (verifyOTP(user_otp, otp)) {
             
            } else {
                 cout << "Invalid OTP entered. Please try again." <<  endl;
                return {"", ""};
            }

           
             ostringstream otp_ss;
            otp_ss << "OTP " << account_number << " " << user_otp << " " << nonce;
             string otp_command = otp_ss.str();

            if (!send_message_with_hmac(ssl, otp_command)) {
                 cerr << "Failed to send OTP command." <<  endl;
                return {"", ""};
            }

            
             string final_response;
            if (receive_message_with_hmac(ssl, final_response)) {
                if (final_response.find("SUCCESS") !=  string::npos) {
                    size_t token_pos = final_response.find("Session Token:");
                    size_t role_pos = final_response.find("Role:");
                    if (token_pos !=  string::npos && role_pos !=  string::npos) {
                        size_t token_start = token_pos + 14;
                        size_t token_end = final_response.find(" ", token_start);
                        if(token_end ==  string::npos){
                            token_end = final_response.length();
                        }
                         string token = final_response.substr(token_start, token_end - token_start);
                         string role = final_response.substr(role_pos + 5);
                        role = sanitize_input(role); 

                        current_session.token = token;
                        current_session.last_active =  chrono::steady_clock::now();
                        current_session.role = role;
                        current_session.account_number = account_number;
                        
                        return {token, role};
                    }
                } else {
                    
                }
            } else {
                
            }
        } else if (response.find("SUCCESS") !=  string::npos) {
            
            size_t token_pos = response.find("Session Token:");
            size_t role_pos = response.find("Role:");
            if (token_pos !=  string::npos && role_pos !=  string::npos) {
                size_t token_start = token_pos + 14;
                size_t token_end = response.find(" ", token_start);
                if(token_end ==  string::npos){
                    token_end = response.length();
                }
                 string token = response.substr(token_start, token_end - token_start);
                 string role = response.substr(role_pos + 5);
                role = sanitize_input(role); 

                
                current_session.token = token;
                current_session.last_active =  chrono::steady_clock::now();
                current_session.role = role;
                current_session.account_number = account_number;
                 cout << "Login successful. Token: " << token << ", Role: " << role <<  endl;  
                return {token, role};
            }
        } else {
             cout << "Login failed. Server response: " << response <<  endl;  
        }
    } else {
         cout << "Failed to receive server response during login." <<  endl;  
    }
    return {"", ""};
}

void transaction_menu(SSL* ssl) {
     cout << "Entering transaction menu..." <<  endl;
    

    if (SSL_get_fd(ssl) == -1) {
         cerr << "SSL connection is not valid at the start of transaction menu." <<  endl;
        return;
    }

    while (true) {
        if (!is_session_active()) {
             cout << "Session expired. Please log in again." <<  endl;
            handle_logout(ssl);
            break;
        }
        update_session_activity();

         cout << "\n--- Transaction Menu ---\n";
         cout << "1. Deposit\n";
         cout << "2. Withdraw\n";
         cout << "3. Check Balance\n";
        if (current_session.role == "ADMIN") {
             cout << "4. Delete Account\n";
             cout << "5. Logout\n";
        } else {
             cout << "4. Logout\n";
        }
         cout << "Enter choice: ";
        int choice;
        if (!( cin >> choice)) {
             cin.clear();
             cin.ignore( numeric_limits< streamsize>::max(), '\n');
             cout << "Invalid input. Please enter a number." <<  endl;
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
                     cout << "Delete Account functionality not implemented yet." <<  endl;
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
                 cout << "Invalid choice. Please try again." <<  endl;
        }
    }
}

void handle_deposit(SSL* ssl) {
    if (SSL_get_fd(ssl) == -1) {
         cerr << "SSL connection is not valid. Cannot perform deposit." <<  endl;
        return;
    }
    double amount;
     cout << "Enter amount to deposit: ";
     cin >> amount;

    if (amount <= 0) {
         cerr << "Invalid amount. Please enter a positive number." <<  endl;
        return;
    }

     ostringstream ss;
    ss << "DEPOSIT " << current_session.token << " " << current_session.account_number << " " <<  fixed <<  setprecision(2) << amount;
     string deposit_command = ss.str();

    if (!send_message_with_hmac(ssl, deposit_command)) {
         cerr << "Failed to send DEPOSIT command." <<  endl;
        return;
    }


     string response;
    if (receive_message_with_hmac(ssl, response)) {
         cout << response <<  endl;
    } else {
         cerr << "Failed to receive or verify server response." <<  endl;
    }
}

void handle_withdraw(SSL* ssl) {
    if (SSL_get_fd(ssl) == -1) {
         cerr << "SSL connection is not valid. Cannot perform withdrawal." <<  endl;
        return;
    }
    double amount;
     cout << "Enter amount to withdraw: ";
     cin >> amount;

    if (amount <= 0) {
         cerr << "Invalid amount. Please enter a positive number." <<  endl;
        return;
    }
   
     ostringstream ss;
    ss << "WITHDRAW " << current_session.token << " " << current_session.account_number << " " <<  fixed <<  setprecision(2) << amount;
     string withdraw_command = ss.str();

    if (!send_message_with_hmac(ssl, withdraw_command)) {
         cerr << "Failed to send WITHDRAW command." <<  endl;
        return;
    }


     string response;
    if (receive_message_with_hmac(ssl, response)) {
         cout << response <<  endl;
    } else {
         cerr << "Failed to receive or verify server response." <<  endl;
    }
}

void handle_check_balance(SSL* ssl) {
    if (SSL_get_fd(ssl) == -1) {
         cerr << "SSL connection is not valid. Cannot check balance." <<  endl;
        return;
    }
     ostringstream ss;
    ss << "CHECK_BALANCE " << current_session.token;
     string check_balance_command = ss.str();

    if (!send_message_with_hmac(ssl, check_balance_command)) {
         cerr << "Failed to send CHECK_BALANCE command." <<  endl;
        return;
    }


     string response;
    if (receive_message_with_hmac(ssl, response)) {
         cout << response <<  endl;
    } else {
         cerr << "Failed to receive or verify server response." <<  endl;
    }
}

void handle_logout(SSL* ssl) {
     ostringstream ss;
    ss << "LOGOUT " << current_session.token;
     string logout_command = ss.str();

    if (!send_message_with_hmac(ssl, logout_command)) {
         cerr << "Failed to send LOGOUT command." <<  endl;
        return;
    }


     string response;
    if (receive_message_with_hmac(ssl, response)) {
         cout << response <<  endl;
        current_session = Session(); 
    } else {
         cerr << "Failed to receive or verify server response." <<  endl;
    }
}

 string request_nonce(SSL* ssl) {
    
    return generate_nonce();
}

 string generate_client_session_token() {
    unsigned char buffer[32]; 
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        log_error("Failed to generate secure random client session token.");
        return "";
    }

   
     stringstream ss;
    for (int i = 0; i < sizeof(buffer); ++i) {
        ss <<  hex <<  setw(2) <<  setfill('0') << (int)buffer[i];
    }
    return ss.str();
}

 string get_executable_path() {
    char result[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    return  string(result, (count > 0) ? count : 0);
}

SSL* reconnect_to_server(SSL_CTX* ctx) {
     cout << "Attempting to reconnect to server..." <<  endl;
    SSL* new_ssl = connect_to_server(ctx);
    if (!new_ssl) {
         cerr << "Failed to reconnect to server." <<  endl;
        return nullptr;
    }
     cout << "Successfully reconnected to server." <<  endl;
    return new_ssl;
}

int main() {
    
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

     string exec_path = get_executable_path();
     string pubkey_path = exec_path.substr(0, exec_path.find_last_of("/")) + "/ssl_certs/public_key.pem";
     ifstream pubkey_file(pubkey_path);
    if (!pubkey_file.good()) {
         cerr << "Error: Unable to open public key file. Please ensure '" << pubkey_path << "' exists and is readable." <<  endl;
        return EXIT_FAILURE;
    }
    pubkey_file.close();

    SSL_CTX* ctx = create_context_client();
    if (!ctx) {
         cerr << "Failed to create SSL context. Exiting." <<  endl;
        return EXIT_FAILURE;
    }

    SSL* ssl = connect_to_server(ctx);
    if (!ssl) {
         cerr << "Failed to connect to server. Exiting." <<  endl;
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

   
    while (true) {
         cout << "\n--- Main Menu ---\n";
         cout << "1. Create Account\n";
         cout << "2. Login\n";
         cout << "3. Exit\n";
         cout << "Enter choice: ";
        int choice;
         cin >> choice;

        switch (choice) {
            case 1:
                create_account(ssl);
                break;
            case 2: {
                 pair< string,  string> login_result = login(ssl);
                 string session_token = login_result.first;
                 string role = login_result.second;
                if (!session_token.empty() && !role.empty()) {
                     cout << "Login successful. Entering transaction menu..." <<  endl;
                    current_session.token = session_token;
                    current_session.role = role;
                    current_session.last_active =  chrono::steady_clock::now();
                    
                   
                    if (SSL_get_fd(ssl) == -1) {
                         cerr << "SSL connection lost after successful login." <<  endl;
                        
                        SSL_free(ssl);
                        ssl = connect_to_server(ctx);
                        if (!ssl) {
                             cerr << "Failed to reconnect to server. Exiting." <<  endl;
                            return EXIT_FAILURE;
                        }
                    }
                    
                    transaction_menu(ssl);
                     cout << "Returned from transaction menu." <<  endl;
                } else {
                     cout << "Login failed. Please try again." <<  endl;
                }
                break;
            }
            case 3:
                handle_logout(ssl);
                cleanup_and_exit(ssl, ctx);
                return 0;
            default:
                 cout << "Invalid choice. Please try again." <<  endl;
        }
    }

    cleanup_and_exit(ssl, ctx);
    return 0;
}
