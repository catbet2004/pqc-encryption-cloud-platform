#include "MLDSA.hpp"
#include <cstdio>
#include <stdexcept>
#include <openssl/err.h>

MLDSA::MLDSA(){
    keypair=EVP_PKEY_Q_keygen(nullptr,nullptr,"ML-DSA-65");

    if(!keypair){
        ERR_print_errors_fp(stderr);

        throw std::runtime_error("Failed to generate ML-DSA-65 keypair.");
    }
}
MLDSA::~MLDSA(){
    EVP_PKEY_free(keypair);
}

std::vector<unsigned char> MLDSA::sign(const std::vector<unsigned char>& message){
    EVP_PKEY_CTX* ctx=
        EVP_PKEY_CTX_new_from_pkey(nullptr,keypair,nullptr);

    if(!ctx){
        ERR_print_errors_fp(stderr);

        throw std::runtime_error("Failed to create ML-DSA signing context.");
    }

    EVP_SIGNATURE* algorithm=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65", nullptr);

    if(!algorithm){
        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to load ML-DSA-65.");

    }

    if(EVP_PKEY_sign_message_init(ctx,algorithm,nullptr)<=0){
        ERR_print_errors_fp(stderr);

        EVP_SIGNATURE_free(algorithm);
        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to initialize ML-DSA signing.");

    }

    size_t signatureLength=0;

    if(EVP_PKEY_sign(ctx,nullptr,&signatureLength,message.data(), message.size())<=0){
        ERR_print_errors_fp(stderr);
        EVP_SIGNATURE_free(algorithm);
        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to determine ML-DSA signature size.");
        
    }
    std::vector<unsigned char> signature(signatureLength);

    if(EVP_PKEY_sign(ctx,signature.data(),&signatureLength,message.data(),message.size())<=0){
        ERR_print_errors_fp(stderr);

        EVP_SIGNATURE_free(algorithm);
        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("ML-DSA signing failed.");
    }
    signature.resize(signatureLength);

    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_CTX_free(ctx);

    return signature;
}

bool MLDSA::verify(
    const std::vector<unsigned char>& message, 
    const std::vector<unsigned char>& signature
){
    //operation context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr,keypair,nullptr);

    if(!ctx){
        ERR_print_errors_fp(stderr);

        throw std::runtime_error("Failed to create ML-DSA verification context.");

    }

    //fetch ml-dsa

    EVP_SIGNATURE* algorithm=EVP_SIGNATURE_fetch(nullptr, "ML-DSA-65", nullptr);

    if(!algorithm){
        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to load ML_DSA-65");
    }

    //OpenSSL will verify signature
    if(EVP_PKEY_verify_message_init(ctx,algorithm,nullptr)<=0){
        ERR_print_errors_fp(stderr);
        EVP_SIGNATURE_free(algorithm);
        EVP_PKEY_CTX_free(ctx);

        throw std::runtime_error("Failed to initialize ML-DSA verification.");
    }

    int result= EVP_PKEY_verify(ctx, signature.data(), signature.size(), message.data(), message.size());

    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_CTX_free(ctx);


    //signature valid
    if(result==1){
        return true;
    }
    //invalid
    if(result==0){
        return false;
    }

    ERR_print_errors_fp(stderr);

    throw std::runtime_error("An error occured during ML-DSA verification.");

    
}





