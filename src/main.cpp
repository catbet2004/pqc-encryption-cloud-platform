#include <iostream>
#include "algos/MLKEM.hpp"

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

        std::cout<<"Shared secret size: "<< userSecret.size()<< " bytes\n";

    } catch(const std::exception& error){
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }

    return 0;

}
