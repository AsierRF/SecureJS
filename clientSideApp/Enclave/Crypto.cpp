#include "Crypto.h"
#include "Enclave.h"
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
/*FOR SIGNATURE*/
sgx_ec256_private_t * my_private = new (sgx_ec256_private_t);
sgx_ec256_public_t * my_public = new  (sgx_ec256_public_t);
sgx_ec256_public_t * javascript_public = new (sgx_ec256_public_t);
/*FOR ENCRYPTION*/
sgx_aes_gcm_128bit_key_t javascript_encryptionKey = {0};
sgx_aes_gcm_128bit_key_t my_encryptionKey = 
{
	0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 
	0x20, 0x61, 0x64, 0x64, 0x28, 0x76, 0x61, 0x6c
};

bool keysGenerated = false;
bool keyReceived = false;
bool dataEncrypted = false;
uint8_t aes_gcm_iv[12] = {0};

int getHash(uint8_t* data, uint32_t size_data, sgx_sha256_hash_t * returnValue);
/*Getter and setter functions*/
bool setEncrypted(){
    dataEncrypted=true;
    return dataEncrypted;
}

bool isEncrypted (){
    return dataEncrypted;
}

int setJavaScriptPublicKey(sgx_ec256_public_t * newPublicKey){
	if(newPublicKey==NULL) return 0;
	javascript_public = newPublicKey;
	keyReceived=true;
	return 1;
}

int setJavaScriptEncryptionKey(sgx_aes_gcm_128bit_key_t newEncryptionKey){
	if(&newEncryptionKey==NULL) return 0;
	for(int i=0; i<16; i++)
	{
		javascript_encryptionKey [i] = newEncryptionKey[i];
	}	
	keyReceived=true;
	return 1;
}

sgx_ec256_public_t * getMyPublicKey (){
	if(!generateKeys) return NULL;
	return my_public;
}

sgx_aes_gcm_128bit_key_t * getMyEncryptionKey (){
	return &my_encryptionKey;
}

/*GENERATE KEYS*/
/*
	Generates the global keys for the client.
	Input:
	Output:	int -> 1 if generation is correct, 0 if error or generation incorrect, -1 if points are not valid
*/
int generateKeys()
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle = NULL;
	sgx_ret = sgx_ecc256_open_context(&ecc_handle);
	int p_valid = 1;
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	/*Create key pair if required*/
	sgx_ret = sgx_ecc256_create_key_pair(my_private, my_public, ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	/*Check public key*/
	sgx_ret = sgx_ecc256_check_point(my_public, ecc_handle, &p_valid);
	if(sgx_ret == SGX_SUCCESS){
		if(p_valid==0){
			return -1;
		}
	}
	/*Close context for sign function*/
	sgx_ret = sgx_ecc256_close_context(ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	keysGenerated=true;
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
int signData(std::string stringValue, sgx_ec256_signature_t * output)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle = NULL;
	int returnValue = 0;

    int value_len = stringValue.length();
    uint8_t data [value_len] = {0};
    for(int i=0; i<value_len;i++){
        data[i]=(uint8_t) stringValue[i];
    }

	if(!keysGenerated){
		return 0; //If there is no keys, can not sign.
	} 
	/*Open context for sign function*/
	sgx_ret = sgx_ecc256_open_context(&ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	/*Generate hash*/
	sgx_sha256_hash_t hash = {0};
	returnValue=getHash(data, (uint32_t) value_len, &hash);
	if(returnValue==0){
		return 0;
	}
	/*Sign data*/
	sgx_ret = sgx_ecdsa_sign((uint8_t *) &hash, sizeof(&hash), my_private, output, ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
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


/*CHECK SIGNATURE*/
/*
	Verifies the signature of the data.
	Input:	uint8_t * data -> pointer to the data to verify
			sgx_ec256_signature_t *p_signature -> pointer to the signature to verity
	Output:	int -> 1 if verifycation is correct, 0 if error, -1 if verifycation incorrect			
*/
int checkSignature(std::string stringValue, sgx_ec256_signature_t * p_signature_to_check)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle = NULL;
	uint8_t p_result = 1;
	int returnValue;
	int value_len = stringValue.length();
    uint8_t data [value_len] = {0};
    for(int i=0; i<value_len;i++){
        data[i]=(uint8_t) stringValue[i];
    }
	if(!keyReceived) return 0;
	/*Open context for verifying function*/
	sgx_ret = sgx_ecc256_open_context(&ecc_handle);
	if(sgx_ret != SGX_SUCCESS)
	{
    	return 0;
	}
	/*Generate hash*/
	sgx_sha256_hash_t hash = {0};
	returnValue=getHash(data, (uint32_t) value_len, &hash);
	if(returnValue==0){
		return 0;
	}
	/*Verify data*/
	sgx_ret = sgx_ecdsa_verify((uint8_t *) &hash, sizeof(&hash), javascript_public, p_signature_to_check, &p_result, ecc_handle);
	if(sgx_ret == SGX_SUCCESS){
		if(p_result!=SGX_EC_VALID){
			return -1;
		}
	}
	else if (sgx_ret == SGX_ERROR_UNEXPECTED){
		return 0;
	}
	else if (sgx_ret == SGX_ERROR_OUT_OF_MEMORY){
		return 0;
	}
	else if (sgx_ret == SGX_ERROR_INVALID_PARAMETER){
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

/*DECRYPT SECRET*/
/*
	Decrypts the given secret and returns the plaintext in hex.
	Input:	std::vector <uint8_t> functionHexEncrypted -> encrypted information to be decrypted
			int functionHex_size -> size of the encrypted information to be decrypted
			uint8_t mac [16] -> MAC value for verification generated during encryption
	Output:	int -> 1 if generation is correct, 0 if error or generation incorrect, -1 if points are not valid
			std::vector <uint8_t> * functionHexDecrypted -> decrypted information in hex
*/
int decryptSecret(std::vector <uint8_t> functionHexEncrypted, int functionHex_size, uint8_t mac [16], 
	std::vector <uint8_t> * functionHexDecrypted)
{
	sgx_status_t ret = SGX_SUCCESS;
	uint8_t p_secret [functionHexEncrypted.size()] = {0};
	uint8_t secret [functionHexEncrypted.size()] = {0};
	if(!keyReceived) return 0;
	for(int i=0; i<functionHexEncrypted.size();i++){
		p_secret[i]=functionHexEncrypted[i];
	}
	ret = sgx_rijndael128GCM_decrypt(&javascript_encryptionKey,
                                         &p_secret[0],
                                         functionHexEncrypted.size(),
                                         &secret[0],
                                         aes_gcm_iv,
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *)
                                            (mac));
	if(ret!=SGX_SUCCESS) return -1;
	for(int i=0; i<functionHexEncrypted.size(); i++){
		functionHexDecrypted->push_back(secret[i]);
	}

	return 1;
}

/*ENCRYPT PLAINTEXT*/
/*
	Encrypts the given plaintext and returns the plaintext in hex.
	Input:	std::vector <uint8_t> textHexDecrypted -> plaintext information to be encrypted
	Output:	int -> 1 if generation is correct, 0 if error or generation incorrect, -1 if points are not valid
			std::vector <uint8_t> * textHexEncrypted -> encrypted information in hex
*/
int encryptPlaintext(std::vector <uint8_t> textHexDecrypted, std::vector <uint8_t> * textHexEncrypted)
{
	sgx_status_t ret = SGX_SUCCESS;
	uint8_t p_secret [textHexDecrypted.size()] = {0};
	uint8_t secret [textHexDecrypted.size()] = {0};
	uint8_t mac [16] = {0};
	if(!keyReceived) return 0;
	for(int i=0; i<textHexDecrypted.size();i++){
		p_secret[i]=textHexDecrypted[i];
	}
	ret = sgx_rijndael128GCM_encrypt(&my_encryptionKey,
                                         &p_secret[0],
                                         textHexDecrypted.size(),
                                         &secret[0],
                                         aes_gcm_iv,
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *)
                                            (&mac));
	if(ret!=SGX_SUCCESS) return -1;
	for(int i=0; i<textHexDecrypted.size(); i++){
		textHexEncrypted->push_back(secret[i]);
	}
	for(int i=0; i<16;i++){
		textHexEncrypted->push_back(mac[i]);
	}

	return 1;
}

/*HASH*/
/*
	Generates the hash of the data.
	Input:	uint8_t * data -> pointer to the data to sign
	Output:	int -> 1 if generation is correct, 0 if error or generation incorrect
			sgx_sha256_hash_t * returnValue -> pointer to the generated hash
*/
int getHash(uint8_t * data, uint32_t size_data, sgx_sha256_hash_t * output)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
	sgx_sha_state_handle_t sha_handle = NULL;

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
	sgx_ret = sgx_sha256_get_hash(sha_handle, output);
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