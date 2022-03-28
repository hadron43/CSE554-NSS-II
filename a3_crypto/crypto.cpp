#include <openssl/evp.h>
#include <openssl/err.h>
#include <bits/stdc++.h>
using namespace std;

#ifndef macros

#define MAX_MESSAGE_SIZE 1024
#define IV_SIZE 16
#define HMAC_SIZE 32
#define MAX_PAYLOAD_SIZE MAX_MESSAGE_SIZE - IV_SIZE - HMAC_SIZE

#endif

unsigned char *pre_shared_key = nullptr, *iv = nullptr;
bool verbose = false;

EVP_CIPHER_CTX *encrypt_ctx = nullptr, *decrypt_ctx = nullptr;
EVP_MD_CTX *sign_ctx = nullptr;
EVP_PKEY *pkey = nullptr;

void destruct_final(void);

void handleError(string str) {
    ERR_print_errors_fp(stderr);
    destruct_final();
    exit(-1);
}

string get_iv() {
    string ret;
    if(iv != nullptr) {
        for(int i = 0; i < IV_SIZE; ++i)
            ret += iv[i];
    }
    return ret;
}

void initialize(string psk, string _iv, bool _verbose = false) {
    if(_iv.length() != IV_SIZE)
        handleError("iv size mismatch");
    pre_shared_key = new unsigned char[psk.length()];
    memset(pre_shared_key, 0, sizeof(pre_shared_key));
    verbose = _verbose;
    for(int i = 0; i < psk.length(); ++i)
        pre_shared_key[i] = psk[i];

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pre_shared_key, psk.length());

    if(verbose)
        cout << "pkey size: " << EVP_PKEY_size(pkey) << "\n";

    iv = new unsigned char[IV_SIZE];
    for(int i = 0; i < IV_SIZE; ++i)
        iv[i] = _iv[i];
}

void initialize(string psk, bool _verbose = false) {
    // generate IV
    string new_iv;
    for(int i = 0; i < IV_SIZE; ++i)
        new_iv += rand() % 255 + 1;
    initialize(psk, new_iv, _verbose);
}

void initialize_encrypt() {
    /**
     * @brief Initialize for encryption
     */
    encrypt_ctx = EVP_CIPHER_CTX_new();
    if(encrypt_ctx == NULL)
        handleError("EVP_CIPHER_CTX_new");

    if(EVP_EncryptInit(encrypt_ctx, EVP_aes_128_cbc(), pre_shared_key, iv) == 0)
        handleError("EVP_EncryptInit");
}

void initialize_decrypt() {
    /**
     * @brief Initialize for decryption
     */
    decrypt_ctx = EVP_CIPHER_CTX_new();
    if(decrypt_ctx == NULL)
        handleError("EVP_CIPHER_CTX_new");

    if(EVP_DecryptInit(decrypt_ctx, EVP_aes_128_cbc(), pre_shared_key, iv) == 0)
        handleError("EVP_DecryptInit");
}

void initialize_sign() {
    sign_ctx = EVP_MD_CTX_new();
    if(sign_ctx == NULL)
        handleError("EVP_MD_CTX_new");

    if(EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, pkey) == 0)
        handleError("EVP_SignInit");
}

void destruct_encrypt() {
    if(encrypt_ctx != nullptr)
        EVP_CIPHER_CTX_free(encrypt_ctx);
}

void destruct_decrypt() {
    if(decrypt_ctx != nullptr)
        EVP_CIPHER_CTX_free(decrypt_ctx);
}

void destruct_sign() {
    if(sign_ctx != nullptr)
        EVP_MD_CTX_free(sign_ctx);
}

void destruct_final() {
    /**
     * @brief free memory
     */

    if(pre_shared_key != nullptr)
        free(pre_shared_key);
    if(pkey != nullptr)
        EVP_PKEY_free(pkey);
    if(iv != nullptr)
        free(iv);
}

string encrypt(string input) {
    int inl = input.length(), outl, temp;
    unsigned char *in = new unsigned char[inl];
    unsigned char *out = new unsigned char[inl * 2];        // extra space for safety

    for(int i = 0; i < inl; ++i)
        in[i] = input[i];     // convert from signed to unsigned

    if(verbose)
        cout << "Text to be encyrpted: " << in << "\n";

    initialize_encrypt();
    if(EVP_EncryptUpdate(encrypt_ctx, out, &outl, in, inl) == 0) {
        free(in);
        free(out);
        handleError("EVP_EncryptUpdate");
    }

    if(EVP_EncryptFinal(encrypt_ctx, out + outl, &temp) == 0) {
        free(in);
        free(out);
        handleError("EVP_EncryptFinal");
    }
    destruct_encrypt();
    outl += temp;

    string cipher_text;
    for(int i = 0; i < outl; ++i)
        cipher_text += out[i];

    if(verbose)
        cout << "Encrypted text (" << outl << ") : " << cipher_text << "\n";

    free(in);
    free(out);
    return cipher_text;
}

string decrypt(string input) {
    int inl = input.length(), outl, temp;
    unsigned char *in = new unsigned char[inl];
    unsigned char *out = new unsigned char[inl * 2];        // extra space for safety

    for(int i = 0; i < inl; ++i)
        in[i] = input[i];     // convert from signed to unsigned

    if(verbose)
        cout << "Text to be decrypted: " << in << "\n";

    initialize_decrypt();
    if(EVP_DecryptUpdate(decrypt_ctx, out, &outl, in, inl) == 0) {
        free(in);
        free(out);
        handleError("EVP_DecryptUpdate");
    }

    if(EVP_DecryptFinal(decrypt_ctx, out + outl, &temp) == 0) {
        free(in);
        free(out);
        handleError("EVP_DecryptFinal");
    }
    destruct_decrypt();
    outl += temp;

    string plain_text;
    for(int i = 0; i < outl; ++i)
        plain_text += out[i];

    if(verbose)
        cout << "Decrypted text (" << outl << ") : " << plain_text << "\n";

    free(in);
    free(out);
    return plain_text;
}

string calculate_hmac(string input) {
    size_t inl = input.length(), outl;
    unsigned char *in = new unsigned char[inl];
    unsigned char *out = new unsigned char[EVP_PKEY_size(pkey)];

    for(int i = 0; i < inl; ++i)
        in[i] = input[i];     // convert from signed to unsigned

    if(verbose)
        cout << "Text to be hashed: " << in << "\n";

    initialize_sign();
    if(EVP_DigestSignUpdate(sign_ctx, in, inl) == 0) {
        free(in);
        free(out);
        handleError("EVP_DigestSignUpdate");
    }

    if(EVP_DigestSignFinal(sign_ctx, out, &outl) == 0) {
        free(in);
        free(out);
        handleError("EVP_DigestSignUpdate");
    }
    destruct_sign();

    string hash;
    for(int i = 0; i < outl; ++i)
        hash += out[i];

    if(verbose)
        cout << "Hash value (" << outl << ") : " << hash << "\n";

    free(in);
    free(out);
    return hash;
}

bool verify_hmac(string input, string hmac) {
    bool temp = verbose;
    verbose = false;
    string new_hmac = calculate_hmac(input);
    verbose = temp;

    bool res = new_hmac == hmac;
    if(verbose)
        cout << (res ? "HMAC Verified\n" : "HMAC Failed\n");
    return res;
}