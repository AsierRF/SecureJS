#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sys/io.h>
#include <fcntl.h>
#include <sstream>
#include <stdint.h>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "Attestation/isv_app.h"
#include "Application.h"

#define DEBUG_ENCLAVE 1

FILE * OUTPUT = fopen ("enclaveDEBUG.txt" , "a");

int main(){
    sgx_launch_token_t token = {0};
    sgx_enclave_id_t eid = 0;
    int update = 0;
    bool repeat = true;
    int outputLenght=0;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_status_t status = SGX_SUCCESS;
    std::stringstream stream;
    std::string data, output;
    outputToFile("Host STARTS");
    while (repeat){
        data=receiveMessageFromExtension();
        if(data != ""){
            /*Create Enclave*/
            if(SGX_SUCCESS != (ret = sgx_create_enclave("./enclave.signed.so", DEBUG_ENCLAVE, &token, &update, &eid, NULL))){
                stream << std::hex << (int) ret;
                outputToFile("Error creating the enclave\n Error 0x"+stream.str());
                sendErrorMessageToExtension("Error creating the enclave");
                return -1;
            }else{
                outputToFile("The enclave has been created properly");
            }
            /*ATTESTATION*/
            if(0!=initAttestation(eid)) {
                outputToFile("Error with the Attestation");
                sendErrorMessageToExtension("Error with Attestation");
                return -1;
            }   
	    outputToFile("Attestation correct");
		/*MuJS*/
            if(SGX_SUCCESS != (ret = ecall_init_MuJS(eid, &status, data.c_str()))) {
                stream << std::hex << (int) ret;
                outputToFile("Error calling the MuJS\n Error 0x"+stream.str());
                sendErrorMessageToExtension("Error calling MuJS");
                return -1;
            }
            if(status!=SGX_SUCCESS) {
                stream << std::hex << (int) status;
                outputToFile("Error inside the MuJS\n Error 0x"+stream.str());
                sendErrorMessageToExtension("Error inside MuJS");
                return -1;
            }
            repeat=false;
        }
    }

    if(SGX_SUCCESS != (ret = sgx_destroy_enclave(eid))){
        stream << std::hex << (int) status;
        outputToFile("Error destroying enclave\n Error 0x"+stream.str());
        return -3;
    }else{
        outputToFile("The enclave has been destroyed properly");
    }
    return 0;

}
/*OUTPUT TO FILE*/
/*
    Write the given text to the output.txt file.
    Input:  std::string str -> text to be written in the file
    Output: 
*/
void outputToFile(std::string str){
    std::ofstream myfile;
    myfile.open ("output.txt", std::ios::app);
    myfile << str+"\n";
    myfile.close();
}

/*SEND MESSAGE TO EXTENSION*/
/*
    Send the given message to the Chrome Extension.
    Input:  std::string message -> text to be sent
    Output: int -> 1 if correct
*/
int sendMessageToExtension(std::string message){
    uint32_t outLen = message.length();
    char *bOutLen = reinterpret_cast<char *>(&outLen);
    std::cout.write(bOutLen, 4);
    std::cout << message << std::flush;
    return 1;
}

/*SEND ERROR MESSAGE TO EXTENSION*/
/*
    Generate the ERROR message to be sent to the Chrome Extension and send it.
    Input:  std::string message -> text add to the ERROR message
    Output: int -> 1 if correct
*/
int sendErrorMessageToExtension(std::string message){
    std::string errorMessage = "{\"ERROR\":\"" + message + "\"}";
    sendMessageToExtension(errorMessage);
    return 1;
}

/*RECEIVE MESSAGE FROM EXTENSION*/
/*
    Receive message from the Chrome Extension.
    Input:  
    Output: std::string -> message received from the Chrome Extension
*/
std::string receiveMessageFromExtension(){
    uint32_t inLen = 0;
    std::cin.read(reinterpret_cast<char*>(&inLen) ,4);
    if(inLen==0){
        return "";
    }
    char *inMsg = new char[inLen];
    std::cin.read(inMsg, inLen);
    std::string message(inMsg); // if you have managed types, use them!
    delete[] inMsg;
    return message;
}

/*OCALL OUTPUT MUJS*/
/*
    Send the result value to the Chrome Extension
    Input:  const char * data -> message to be sent to the Chrome Extension
    Output:
*/
void ocall_outputMuJS(const char * data){
    std::string str(data, strlen(data));
    sendMessageToExtension(str);
}