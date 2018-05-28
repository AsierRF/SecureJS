#include <string.h>
#include <string>
#include "sgx_tcrypto.h"
#include "Enclave_t.h"
#include "../App/sample_libcrypto.h"

sgx_status_t ecall_getPublicKey(uint8_t * encryptedPublicKey, uint8_t * mac, uint8_t * secret_key, sample_ec256_public_t * p_public)
{
	uint8_t aes_gcm_iv[12] = {0};
	uint8_t decrypted_value [64] = {0};
    sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) secret_key,
                                     encryptedPublicKey,
                                     64,
                                     &(decrypted_value[0]),
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t *)
                                        (mac));
	for(int i=0;i<32;i++){
		p_public->gx[i]=decrypted_value[i];
		p_public->gy[i]=decrypted_value[i+32];
	}
	return SGX_SUCCESS;
}


sgx_status_t ecall_getKey(uint8_t * encryptedKey, uint8_t * mac, uint8_t * secret_key, uint8_t * p_key)
{
    uint8_t aes_gcm_iv[12] = {0};
    uint8_t decrypted_value [80] = {0};
    sgx_status_t ret = SGX_SUCCESS;
    ret = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) secret_key,
                                     encryptedKey,
                                     80,
                                     &(decrypted_value[0]),
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t *)
                                        (mac));
    for(int i=0;i<80;i++){
        p_key[i]=decrypted_value[i];
    }
    return SGX_SUCCESS;
}