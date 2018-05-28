#include "Enclave_u.h"
#include "sgx_urts.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <string>
#include <sstream>
#include "sgx_tcrypto.h"

#define DEBUG_ENCLAVE 1

#define USAGE "fileOutput(0=use stdout[defualt],1=use file as output) dataToCheck signatureOfData PublicKey(optional, if not given, hardcoded publicKey used)"

int createKeyPair = 0; //If false, the hardcoded will be used
bool fileOutput = false; //If false, output will be shown in stdout, if true output to file
FILE * OUTPUT = stdout;

sgx_ec256_public_t publicKey = {
    {
        0x52, 0x76, 0x42, 0x22, 0xc4, 0x47, 0xf7, 0x1e,
        0x45, 0x1c, 0xbe, 0x22, 0x9b, 0x93, 0x39, 0x25,
        0xf6, 0xb2, 0x55, 0x8, 0x3f, 0x25, 0xc7, 0x63,
        0x57, 0x20, 0x2e, 0x74, 0x6f, 0xd0, 0x11, 0x3
    },
    {
        0x5a, 0x9c, 0x71, 0x37, 0x1, 0x9f, 0xef, 0xf7,
        0xa0, 0x1c, 0x8c, 0xb3, 0x2d, 0x64, 0x37, 0x1d,
        0x19, 0x9a, 0xa6, 0x9f, 0x73, 0x52, 0x39, 0x9e,
        0x0, 0xe1, 0x36, 0x14, 0x9d, 0x61, 0x66, 0x79
    }
};
sgx_ec256_signature_t p_signature_to_check = {
    {
    0x2c201ec9, 0x84a9cfcd, 0x7e7814c0, 0x7fb5, 0x7be79000, 0x7fb5, 0x0, 0x0
    },
    {
    0x6802ab9, 0x831e64b4, 0x7e7814c0, 0x7fb5, 0x7be79000, 0x7fb5, 0x0, 0x0 
    }
};

void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);
void PRINT_BYTE_ARRAY_32(FILE *file, void *mem, uint32_t len);
void PRINT_BYTE_ARRAY_SIGNATURE(FILE *file, void *mem, uint32_t len, void *mem2, uint32_t len2);
void ocall_getUint8_t(uint8_t *pointer, uint32_t size, int order);
void ocall_getUint32_t(uint32_t *pointer, uint32_t size, int order);
void ocall_signatureCheck(const char * data);
int getPublicKeyFromString(char * data, sgx_ec256_public_t * output);
int getSignatureFromString(char * data, sgx_ec256_signature_t * output);

int main (int argc, char * argv[])
{
	sgx_launch_token_t token = {0};
    sgx_enclave_id_t eid = 0;
    int update = 0;
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ret = SGX_SUCCESS;
    int myret = 0;
	std::stringstream stream;

	if(argc<4){
		printf("%s\n", USAGE);
		return 0;
	}
    if(*argv[1]=='1') fileOutput =true;
    fprintf(OUTPUT, "\n################################################\n");
    std::string data(argv[2]);
    std::string signature(argv[3]);
    if(fileOutput) OUTPUT = fopen ("sgxChecked.txt" , "a");
	/*myret = getSignatureFromString(argv[3], &p_signature_to_check);
    if(myret==0){
        fprintf(OUTPUT, "ERROR WITH SIGNATURE\n");
        return 0;
    }*/

    if(argc==5) {
        myret = getPublicKeyFromString(argv[4], &publicKey);
    	if(myret==0){
            fprintf(OUTPUT, "ERROR WITH NEW PUBLIC KEY\n");
            return 0;
        }
    }

    ret = sgx_create_enclave("./enclave.signed.so", DEBUG_ENCLAVE, &token, &update, &eid, NULL);
    if(ret != SGX_SUCCESS)
    {
        stream << std::hex << (int) ret;
        fprintf(OUTPUT, "Error creating the enclave\n Error 0x%s",stream.str().c_str());
        return -1;
    }

    //fprintf(OUTPUT, "Data to check: %s\n", argv[2]);
    //fprintf(OUTPUT, "Signature\n");
    //PRINT_BYTE_ARRAY_32(OUTPUT, p_signature_to_check.x, (sizeof(p_signature_to_check.x)/sizeof(p_signature_to_check.x[0])) );
    //PRINT_BYTE_ARRAY_32(OUTPUT, p_signature_to_check.y, (sizeof(p_signature_to_check.y)/sizeof(p_signature_to_check.y[0])) );
    if(argc==5){
        fprintf(OUTPUT, "New Public Key\n");
        PRINT_BYTE_ARRAY(OUTPUT, publicKey.gx, (sizeof(publicKey.gx)/sizeof(publicKey.gx[0])) );
        PRINT_BYTE_ARRAY(OUTPUT, publicKey.gy, (sizeof(publicKey.gy)/sizeof(publicKey.gy[0])) );
    }

    ret = ecall_init_SignatureCheck(eid, &status, data.c_str(), &publicKey, signature.c_str() );
    if(ret == SGX_ERROR_UNEXPECTED || ret!=SGX_SUCCESS)
    {
        stream << std::hex << (int) ret;
        fprintf(OUTPUT, "Error calling the SignatureCheck\n Error 0x%s",stream.str().c_str());
        return -1;
    }

    ret = sgx_destroy_enclave(eid);
    if(ret != SGX_SUCCESS)
    {
        stream << std::hex << (int) status;
        fprintf(OUTPUT, "Error destroying the enclave\n Error 0x%s",stream.str().c_str());
        return -1;
    }

    fprintf(OUTPUT, "\n################################################\n");

    return 0;
}	

void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

void PRINT_BYTE_ARRAY_32(FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint32_t *array = (uint32_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

void PRINT_BYTE_ARRAY_SIGNATURE(FILE *file, void *mem, uint32_t len, void *mem2, uint32_t len2)
{
    if(!mem || !len || !mem2 || !len2)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint32_t *array = (uint32_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len+len2);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x", array[i]);
    }
    fprintf(file, "0x%x", array[i]);
    array = (uint32_t *)mem2;
    for(i = 0; i < len2 - 1; i++)
    {
        fprintf(file, "0x%x", array[i]);
    }
    fprintf(file, "0x%x", array[i]);
    fprintf(file, "\n}\n");
}

void ocall_getUint8_t(uint8_t *pointer, uint32_t size, int order){
    switch(order){
        case 0:
            fprintf(OUTPUT, "\n---------------------\nENCLAVE PUBLIC KEY :\n");
            PRINT_BYTE_ARRAY(OUTPUT, pointer, size);
            break;
        case 1:
            PRINT_BYTE_ARRAY(OUTPUT, pointer, size);
            break;
        case 2:
            fprintf(OUTPUT, "\n---------------------\nENCLAVE PRIVATE KEY :\n");
            PRINT_BYTE_ARRAY(OUTPUT, pointer, size);
            break;
        case 3:
            fprintf(OUTPUT, "\n---------------------\nENCLAVE HASH :\n");
            PRINT_BYTE_ARRAY(OUTPUT, pointer, size);
            break;
        default:
            fprintf(OUTPUT, "\n---------------------\nENCLAVE DEFAULT :\n");
            break;
    }
}

void ocall_getUint32_t(uint32_t *pointer, uint32_t size, int order){
    switch(order){
        case 0:
            fprintf(OUTPUT, "\n---------------------\nENCLAVE SIGNATURE :\n");
            PRINT_BYTE_ARRAY_32(OUTPUT, pointer, size);
            break;
        case 1:
            PRINT_BYTE_ARRAY_32(OUTPUT, pointer, size);
            break;
        default:
            fprintf(OUTPUT, "\n---------------------\nENCLAVE DEFAULT :\n");
            break;
    }
}

void ocall_signatureCheck(const char * data){
    fprintf(OUTPUT, "\n---------------------\nSIGNATURE :\n%s\n", data);
}

int getPublicKeyFromString(char * data, sgx_ec256_public_t * output)
{
    std::string signatureData(data);
    std::string hex;
    bool found=false;
    int countFoundx = 0, countFoundy=0;
    int start=0;
    for(int i=1; i<signatureData.length();i++){
        if(signatureData.substr(i-1,2).compare("0x")==0){
            start=i+1;
            i++;
            while(signatureData.substr(i-1,2).compare("0x")!=0 &&
                            i<=signatureData.length()) 
                i++;
            hex=signatureData.substr(start, i-1-start);
            //fprintf(OUTPUT, "Found hex %s\n", hex.c_str());
            if(countFoundx<sizeof(output->gx)){
                output->gx[countFoundx] = (uint8_t) strtol(hex.c_str(), NULL, 16);
                //fprintf(OUTPUT, "Value X %u\n", output->gx[countFoundx]);
                countFoundx++;
            }
            else if (countFoundy<sizeof(output->gy)) {
                output->gy[countFoundy] = (uint8_t) strtol(hex.c_str(), NULL, 16);
                //fprintf(OUTPUT, "Value Y %u\n", output->gy[countFoundy]);
                countFoundy++;
            }
            else {
                i=signatureData.length()+1;
            }
            if(!found) found=true;
            i--;
        }
    }
    if(!found) return 0;
    return 1;
}
int getSignatureFromString(char * data, sgx_ec256_signature_t * output)
{
    std::string signatureData(data);
    std::string hex;
    bool found=false;
    int countFoundx = 0, countFoundy=0;
    int start=0;
    for(int i=1; i<signatureData.length();i++){
        if(signatureData.substr(i-1,2).compare("0x")==0){
            start=i+1;
            i++;
            while(signatureData.substr(i-1,2).compare("0x")!=0 &&
                            i<=signatureData.length()) 
                i++;
            hex=signatureData.substr(start, i-1-start);
            if(countFoundx< (sizeof(output->x)/sizeof(output->x[0])) ){
                output->x[countFoundx] = (uint32_t) strtol(hex.c_str(), NULL, 16);
                countFoundx++;
            }
            else if (countFoundy<(sizeof(output->y)/sizeof(output->y[0])) ) {
                output->y[countFoundy] = (uint32_t) strtol(hex.c_str(), NULL, 16);
                countFoundy++;
            }
            else {
                i=signatureData.length()+1;
            }
            if(!found) found=true;
            i--;
        }
    }
    if(!found) return 0;
    return 1;
}