#include <string.h>
#include <string>
#include "sgx_tcrypto.h"
#include "Enclave_t.h"

sgx_ec256_signature_t p_signature = {0};

int getHash(uint8_t* data, uint32_t size_data, sgx_sha256_hash_t * returnValue);
int checkSignature(uint8_t * data, sgx_ec256_public_t * p_public, sgx_ec256_signature_t * p_signature_to_check);
int getSignatureFromString(const char * data, sgx_ec256_signature_t * output);

sgx_status_t ecall_init_SignatureCheck(const char * stringValue, sgx_ec256_public_t * p_public,
 const char * signature)
{
	sgx_sha256_hash_t p_hash = {0};
	int ret=0;
	int value_len = strlen(stringValue);
	ocall_signatureCheck("Signature generator, stringValue size.");
	ocall_getUint8_t((uint8_t *) &value_len, 1, 3);
    uint8_t data [value_len] = {0};
    for(int i=0; i<value_len;i++){
        data[i]=(uint8_t) stringValue[i];
    }

	if(getHash(data, (uint32_t) value_len, &p_hash)!=1){
		return SGX_ERROR_UNEXPECTED;
	}
	ocall_signatureCheck(signature);
	sgx_ec256_signature_t * p_signature = new (sgx_ec256_signature_t);
	ret = getSignatureFromString(signature, p_signature);
	if(ret==0){
        return SGX_ERROR_UNEXPECTED;
    }
	ocall_getUint32_t(p_signature->x, (sizeof(p_signature->x)/sizeof(p_signature->x[0])) , 0);
	ocall_getUint32_t(p_signature->y, (sizeof(p_signature->y)/sizeof(p_signature->y[0])) , 1);
	ocall_getUint8_t(p_public->gx, (sizeof(p_public->gx)/sizeof(p_public->gx[0])), 0);
	ocall_getUint8_t(p_public->gy, (sizeof(p_public->gy)/sizeof(p_public->gy[0])), 1);
	ocall_getUint8_t(&(p_hash[0]), 32, 3);
	ret=checkSignature((uint8_t *) &p_hash, p_public, p_signature);
	if(ret==0){
		return SGX_ERROR_UNEXPECTED;
	}
	else if(ret==-1){
		ocall_signatureCheck("Signature checked, not good.");
		return SGX_ERROR_UNEXPECTED;
	}

	ocall_signatureCheck("Signature checked, everything okay.");
	
	return SGX_SUCCESS;
}

/*HASH*/
/*
	Generates the hash of the data.
	Input:	uint8_t * data -> pointer to the data to sign
	Output:	int -> 1 if generation is correct, 0 if error or generation incorrect
			sgx_sha256_hash_t * returnValue -> pointer to the generated hash
*/
int getHash(uint8_t * data, uint32_t size_data, sgx_sha256_hash_t * returnValue)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_sha_state_handle_t sha_handle = NULL;

	ocall_signatureCheck("DATA BEFORE HASH");
	ocall_getUint8_t(data, size_data, 3);

	sgx_ret = sgx_sha256_init(&sha_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
	    return 0;
	}
	sgx_ret = sgx_sha256_update( data, size_data, sha_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
	    return 0;
	}
	sgx_ret = sgx_sha256_get_hash(sha_handle, returnValue);
	if(sgx_ret != SGX_SUCCESS)
	{
	    return 0;
	}

	sgx_ret = sgx_sha256_close(sha_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
	    return 0;
	}

	return 1;
}

/*CHECK SIGNATURE*/
/*
	Verifies the signature of the data.
	Input:	uint8_t * data -> pointer to the data to verify
			sgx_ec256_public_t *p_public -> pointer to the public key
			sgx_ec256_signature_t *p_signature -> pointer to the signature to verity
	Output:	int -> 1 if verifycation is correct, 0 if error, -1 if verifycation incorrect			
*/
int checkSignature(uint8_t * data, sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature_to_check)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle = NULL;
	uint8_t p_result = 1;
	/*Open context for verifying function*/
	sgx_ret = sgx_ecc256_open_context(&ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	/*Verify data*/
	sgx_ret = sgx_ecdsa_verify(data, sizeof(data), p_public, p_signature_to_check, &p_result, ecc_handle);
	if(sgx_ret == SGX_SUCCESS){
		if(p_result!=SGX_EC_VALID){
			return -1;
		}
	}
	else if (sgx_ret == SGX_ERROR_UNEXPECTED){
		ocall_signatureCheck("The verification process failed due to an internal cryptography library failure.");
		return 0;
	}
	else if (sgx_ret == SGX_ERROR_OUT_OF_MEMORY){
		ocall_signatureCheck("Not enough memory is available to complete this operation.");
		return 0;
	}
	else if (sgx_ret == SGX_ERROR_INVALID_PARAMETER){
		ocall_signatureCheck("The ECC context handle, public key, data, result or signature pointer is NULL or the data size is 0.");
		return 0;
	}
	
	/*Close context for verifying function*/
	sgx_ret = sgx_ecc256_close_context(ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	return 1;
}

int getPublicKeyFromString(const char * data, sgx_ec256_public_t * output)
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

int getSignatureFromString(const char * data, sgx_ec256_signature_t * output)
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
            if(countFoundx< (sizeof(output->x)/sizeof(output->x[0])) ){
                output->x[countFoundx] = (uint32_t) strtol(hex.c_str(), NULL, 16);
                //fprintf(OUTPUT, "Value X %x\n", output->x[countFoundx]);
                countFoundx++;
            }
            else if (countFoundy<(sizeof(output->y)/sizeof(output->y[0])) ) {
                output->y[countFoundy] = (uint32_t) strtol(hex.c_str(), NULL, 16);
                //fprintf(OUTPUT, "Value Y %x\n", output->y[countFoundy]);
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