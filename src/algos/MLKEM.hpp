#pragma once

#include <vector>
#include <openssl/evp.h>

struct EncapsResult{
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> sharedSecret;
};

class MLKEM{
    public:
        MLKEM();
        ~MLKEM();

        MLKEM(const MLKEM&)=delete;
        MLKEM& operator=(const MLKEM&)=delete;

        EncapsResult encapsulate();

        std::vector<unsigned char> decapsulate(
            const std::vector<unsigned char>& ciphertext
        );
    private:
        EVP_PKEY* keypair = nullptr;
};