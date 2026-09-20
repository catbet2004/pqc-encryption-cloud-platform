#include <iostream>
#include <string>
#include <vector>
#include "algos/MLKEM.hpp"
#include "algos/MLDSA.hpp"


int main(){
    try{
        MLKEM kem;

        std::cout<<"MLKEM-768 keypair generated.\n";

        auto encapsulation=kem.encapsulate();

        std::cout<<"Encapsulation successful.\n";

        auto userSecret=kem.decapsulate(encapsulation.ciphertext);

        std::cout<<"Decapsulation successful.\n";

        if(encapsulation.sharedSecret==userSecret){
            std::cout <<"SUCCESS: Shared secrets match!\n";
        } else{
            std::cerr<<"FAILURE: Shared secrets do not match.\n";

            return 1;
        }

        std::cout<<"Shared secret size: "<< userSecret.size()<< " bytes\n\n";

        MLDSA signer;

        std::cout<<"ML_DSA-65 keypair generated.\n";

        std::string text="Post-quantum secure cloud";

        std::vector<unsigned char> message(text.begin(), text.end());

        auto signature=signer.sign(message);

        std::cout << "Message signed successfully.\n";

        if(signer.verify(message,signature)){
            std::cout<<"SUCCESS: Signature is valid!\n";

        } else{
            std::cout<<"FAILURE: Signature is invalid.\n";
        }

        //tampering test

        std::string changedText="Post-qunatum insecure cloud";

        std::vector<unsigned char> changedMessage(changedText.begin(), changedText.end());

        if(signer.verify(changedMessage, signature)){
            std::cout<<"WARNING: Tampered message passed!\n";
        } else{
            std::cout<< "SUCCESS: Tampering detected!\n";
        }

    } catch(const std::exception& error){
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }

    return 0;

}
