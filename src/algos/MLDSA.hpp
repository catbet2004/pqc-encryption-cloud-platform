#pragma once
#include <vector>
#include <openssl/evp.h>

class MLDSA{
public:

    MLDSA();

    ~MLDSA();

    MLDSA(const MLDSA&)=delete;

    MLDSA& operator=(const MLDSA&)=delete;

    std::vector<unsigned char>sign(const std::vector<unsigned char>& message);

    bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature);

private:
    EVP_PKEY* keypair=nullptr;


};