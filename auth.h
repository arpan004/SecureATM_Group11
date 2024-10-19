#ifndef AUTH_H
#define AUTH_H

#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <iomanip>


std::string hashPassword(const std::string &password, const std::string &salt) {
    const int iterations = 10000;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          iterations, EVP_sha256(), sizeof(hash), hash) != 1) {
        return "";
    }

    hash_len = EVP_MD_size(EVP_sha256());

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}


std::string generateSalt(int length = 16) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

    std::string salt;
    for (int i = 0; i < length; ++i) {
        salt += alphanum[dis(gen)];
    }
    return salt;
}


std::string generateOTP() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    return std::to_string(dis(gen));
}


bool verifyOTP(const std::string& user_otp, const std::string& stored_otp) {
    return user_otp == stored_otp;
}

#endif
