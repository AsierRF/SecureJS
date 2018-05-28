#include "Enclave_u.h"
#include "sgx_urts.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <string>
#include <vector>
#include <sstream>
#include "sgx_tcrypto.h"

#define DEBUG_ENCLAVE 1

#define USAGE "fileOutput(0=use stdout[default],1=use file as output) dataToDecrypt "

int createKeyPair = 0; //If false, the hardcoded will be used
bool fileOutput = false; //If false, output will be shown in stdout, if true output to file
FILE* OUTPUT = stdout;

uint8_t key [16] = 
{
    0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 
    0x20, 0x61, 0x64, 0x64, 0x28, 0x76, 0x61, 0x6c
};

void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);
void PRINT_BYTE_ARRAY_32(FILE *file, void *mem, uint32_t len);
void PRINT_BYTE_ARRAY_SIGNATURE(FILE *file, void *mem, uint32_t len, void *mem2, uint32_t len2);
void ocall_getUint8_t(uint8_t *pointer, uint32_t size, int order);
void ocall_getUint32_t(uint32_t *pointer, uint32_t size, int order);
void ocall_signatureCheck(const char * data);
void PRINT_BYTE_ARRAY_E(FILE *file, void *mem, uint32_t len);
int getEncryptionFromString(std::string code, std::vector <uint8_t> * codeHex);


int main (int argc, char * argv[])
{
	sgx_launch_token_t token = {0};
    sgx_enclave_id_t eid = 0;
    int update = 0;
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ret = SGX_SUCCESS;
	std::stringstream stream;
    
	if(argc<3){
		printf("%s\n", USAGE);
		return 0;
	}
    if(*argv[1]=='1') fileOutput =true;
	if(fileOutput) OUTPUT = fopen ("sgxOutputFile.txt" , "a");
    std::string data(argv[2]);
    fprintf(OUTPUT, "\n################################################\n");
    fprintf(OUTPUT, "Data to decrypt: %s\n", data.c_str());
    fprintf(OUTPUT, "Size of data: %zu\n", data.length());
    std::vector <uint8_t> vectorHex;
    if(getEncryptionFromString(data, &vectorHex)==0)
    {
        fprintf(OUTPUT, "Error in getEncryptionFromString");
        return 0;
    }
    int result_size = vectorHex.size()-16;
    uint8_t macHex [16] = {0};
    uint8_t dataHex [result_size] = {0};
    for(int i=0; i<result_size; i++)
    {
        dataHex[i]=vectorHex[i];
    }
    for(int i=0; i<16; i++)
    {
        macHex[i]=vectorHex[result_size+i];
    }
	if(SGX_SUCCESS != (ret = sgx_create_enclave("./enclave.signed.so", DEBUG_ENCLAVE, &token, &update, &eid, NULL)))
	{
        stream << std::hex << (int) ret;
        fprintf(OUTPUT, "Error creating the enclave\n Error 0x%s",stream.str().c_str());
        return -1;
    }

    if(SGX_SUCCESS != (ret = ecall_decrypt(eid, &status, dataHex, result_size, key, macHex))) 
    {
        if(status!=SGX_SUCCESS)
        {
            stream << std::hex << (int) ret;
            fprintf(OUTPUT, "Error in the decryption\n Error 0x%s",stream.str().c_str());
            return -1;
        }
        stream << std::hex << (int) ret;
        fprintf(OUTPUT, "Error calling Decrypt\n Error 0x%s",stream.str().c_str());
        return -1;
    }
    fprintf(OUTPUT, "\n---------------------\nEncryption MAC:\n");
    for(int i=0; i<16; i++)
    {
        fprintf(OUTPUT, "0x%x",  vectorHex[i+result_size]);
    }
    fprintf(OUTPUT, "\n---------------------\nEncrypted value:\n");
    for(int i=0; i<result_size; i++)
    {
        fprintf(OUTPUT, "0x%x",  vectorHex[i]);
    }
    fprintf(OUTPUT, "\n| | | | | | | | | | | | | | | | | | | | | | ");
    fprintf(OUTPUT, "\nV V V V V V V V V V V V V V V V V V V V V V ");
    fprintf(OUTPUT, "\n---------------------\nDecrypted value:\n");
    for(int i=0; i<result_size; i++)
    {
        fprintf(OUTPUT, "%c", (char) dataHex[i]);
    }

    if(SGX_SUCCESS != (ret = sgx_destroy_enclave(eid)))
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
    fprintf(file, "%x bytes:\n{\n", len);
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
			for(int i=0; i<size;i++){
				//publicKey.gx[i]=pointer[i];
			}
			break;
		case 1:
			PRINT_BYTE_ARRAY(OUTPUT, pointer, size);
			for(int i=0; i<size;i++){
				//publicKey.gy[i]=pointer[i];
			}
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
			break;
	}
}

void ocall_getUint32_t(uint32_t *pointer, uint32_t size, int order){
    switch(order){
        case 0:
            fprintf(OUTPUT, "\n---------------------\nENCLAVE ENCRYPTED DATA :\n");
            PRINT_BYTE_ARRAY_32(OUTPUT, pointer, size);
            for(int i=0; i<size;i++){
                //p_signature.x[i]=pointer[i];
            }
            break;
        case 1:
            PRINT_BYTE_ARRAY_32(OUTPUT, pointer, size);
            for(int i=0; i<size;i++){
                //p_signature.y[i]=pointer[i];
            }
            break;
        default:
            break;
    }
}

void ocall_signatureCheck(const char * data){
    fprintf(OUTPUT, "\n---------------------\nENCLAVE :\n%s\n", data);
}

void PRINT_BYTE_ARRAY_E(FILE *file, void *mem, uint32_t len)
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
        fprintf(file, "0x%x", array[i]);
    }
    fprintf(file, "0x%x", array[i]);
    fprintf(file, "\n}\n");
}

int getEncryptionFromString(std::string code, std::vector <uint8_t> * codeHex)
{
    std::string hex;
    bool found=false;
    int start=0;
    for(int i=1; i<code.length();i++){
        if(code.substr(i-1,2).compare("0x")==0){
            start=i+1;
            i++;
            while(code.substr(i-1,2).compare("0x")!=0 &&
                            i<=code.length()) 
                i++;
            hex=code.substr(start, i-1-start);
            //fprintf(OUTPUT, "Found hex %s\n", hex.c_str());
            codeHex->push_back((uint8_t) strtol(hex.c_str(), NULL, 16));
            //fprintf(OUTPUT, "Value X %x\n", output->x[countFoundx]);
            if(!found) found=true;
            i--;
        }
    }
    if(!found) return 0;
    return 1;
}