#include <string.h>
#include <string>
#include "sgx_tcrypto.h"
#include "Enclave_t.h"
#include "sgx_tkey_exchange.h"

sgx_ec256_private_t privateKey = 
{
	0xe6, 0x9a, 0xe6, 0xbc, 0x67, 0x61, 0xcb, 0xbe,
	0x72, 0xc0, 0x62, 0x80, 0x38, 0x4c, 0xd3, 0x44,
	0xc8, 0xe7, 0x4e, 0x60, 0xb1, 0x97, 0x7a, 0x2d,
	0xe3, 0x37, 0xf5, 0xdf, 0x34, 0x2d, 0xc6, 0x69
};
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

int createKeyPair = 0;

int getHash(uint8_t* data, uint32_t size_data, sgx_sha256_hash_t * returnValue);
int getSignature(uint8_t *p_data, sgx_ec256_signature_t *p_signature);

sgx_status_t ecall_init_Signature(const char * stringValue, int createKey){
	sgx_sha256_hash_t p_hash = {0};
	sgx_ec256_signature_t p_signature = {0};
	createKeyPair=createKey;
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
	ret=getSignature((uint8_t *) &p_hash, &p_signature);
	if(ret==0){
		return SGX_ERROR_UNEXPECTED;
	}
	else if(ret==-1){
		ocall_signatureCheck("Signature generator, not good.");
		return SGX_ERROR_UNEXPECTED;
	}

	ocall_getUint32_t(p_signature.x, (sizeof(p_signature.x)/sizeof(p_signature.x[0])) , 0);
	ocall_getUint32_t(p_signature.y, (sizeof(p_signature.y)/sizeof(p_signature.y[0])) , 1);
	ocall_getUint8_t(publicKey.gx, (sizeof(publicKey.gx)/sizeof(publicKey.gx[0])), 0);
	ocall_getUint8_t(publicKey.gy, (sizeof(publicKey.gy)/sizeof(publicKey.gy[0])), 1);
	ocall_getUint8_t(privateKey.r, (sizeof(privateKey.r)/sizeof(privateKey.r[0])), 2);
	ocall_getUint8_t(&(p_hash[0]), 32, 3);
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

/*SIGNATURE*/
/*
	Generates the signature of the data.
	Warning: it uses global privateKey and publicKey, must be initialized before calling this function
	Input:	uint8_t * data -> pointer to the data to sign
	Output:	int -> 1 if generation is correct, 0 if error or generation incorrect, -1 if points are not valid
			sgx_ec256_signature_t *p_signature -> pointer to the signature
*/
int getSignature(uint8_t *p_data, sgx_ec256_signature_t *p_signature)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle = NULL;
	int p_valid = 1;
	/*Open context for sign function*/
	sgx_ret = sgx_ecc256_open_context(&ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	/*Create key pair if required*/
	if(createKeyPair==1){
		sgx_ret = sgx_ecc256_create_key_pair(&privateKey, &publicKey, ecc_handle);
		if(sgx_ret != SGX_SUCCESS)
		{
	    	return 0;
		}
	}
	/*Sign data*/
	sgx_ret = sgx_ecdsa_sign(p_data, sizeof(p_data), &privateKey, p_signature, ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	/*Check public key*/
	sgx_ret = sgx_ecc256_check_point(&publicKey, ecc_handle, &p_valid);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	if(p_valid==0){
		return -1;
	}
	/*Close context for sign function*/
	sgx_ret = sgx_ecc256_close_context(ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	return 1;
}
