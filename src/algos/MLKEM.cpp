#include "MLKEM.hpp"
#include <cstdio>
#include <stdexcept>
#include <openssl/err.h>

MLKEM::MLKEM(){
    keypair=EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768");

    if(!keypair){
        ERR_print_errors_fp(stderr);

        throw std::runtime_error("Failed to generate ML-KEM-768 keypair.");
    }
}

MLKEM::~MLKEM(){
    EVP_PKEY_free(keypair);
}

EncapsResult MLKEM::encapsulate(){
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_from_pkey(nullptr,keypair,nullptr);


    if (!ctx) {

        ERR_print_errors_fp(stderr);

        throw std::runtime_error("Failed to create encapsulation context.");
    }

    if (EVP_PKEY_encapsulate_init(ctx,nullptr)<=0) {

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to initialize ML-KEM encapsulation.");
    }

    size_t ciphertextLength=0;
    size_t secretLength=0;


    if (EVP_PKEY_encapsulate(ctx,nullptr,&ciphertextLength,nullptr,&secretLength)<=0) {

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to determine encapsulation output sizes.");
    }

    EncapsResult result;

    result.ciphertext.resize(ciphertextLength);
    result.sharedSecret.resize(secretLength);

    if (EVP_PKEY_encapsulate(ctx,result.ciphertext.data(),&ciphertextLength,result.sharedSecret.data(),&secretLength)<=0) {

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("ML-KEM encapsulation failed.");
    }

    result.ciphertext.resize(ciphertextLength);
    result.sharedSecret.resize(secretLength);

    EVP_PKEY_CTX_free(ctx);

    return result;
}

//decapsulation
std::vector<unsigned char> MLKEM::decapsulate(const std::vector<unsigned char>& ciphertext) {

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_from_pkey(
            nullptr,
            keypair,
            nullptr
        );

    if (!ctx) {

        ERR_print_errors_fp(stderr);

        throw std::runtime_error(
            "Failed to create decapsulation context."
        );
    }
    
    if (EVP_PKEY_decapsulate_init(ctx,nullptr)<=0) {

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to initialize ML-KEM decapsulation.");
    }

    size_t secretLength = 0;

    if (EVP_PKEY_decapsulate(ctx,nullptr,&secretLength,ciphertext.data(),ciphertext.size())<=0) {

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to determine decapsulated secret size.");
    }

    std::vector<unsigned char> sharedSecret(
        secretLength
    );


    // Actually perform decapsulation.
    if (EVP_PKEY_decapsulate(
            ctx,

            sharedSecret.data(),
            &secretLength,

            ciphertext.data(),
            ciphertext.size()
        ) <= 0) {

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error(
            "ML-KEM decapsulation failed."
        );
    }

    sharedSecret.resize(secretLength);

    EVP_PKEY_CTX_free(ctx);


    return sharedSecret;
}
