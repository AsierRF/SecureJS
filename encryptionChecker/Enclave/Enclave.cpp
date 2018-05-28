#include <string.h>
#include <string>
#include "sgx_tcrypto.h"
#include "Enclave_t.h"
#include "sgx_tkey_exchange.h"

uint8_t aes_gcm_iv[12] = {0};

sgx_status_t ecall_decrypt(uint8_t * data, uint32_t size, uint8_t * key, uint8_t * mac)
{
	sgx_status_t ret = SGX_SUCCESS;
	uint8_t returnAux [size] = {0};
	ret = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *)key,
                                     data,
                                     size,
                                     &returnAux[0],
                                     aes_gcm_iv,
                                     12,
                                     NULL,
                                     0,
                                     (sgx_aes_gcm_128bit_tag_t *)
                                        (mac));
    if(ret!=SGX_SUCCESS) ocall_signatureCheck("ERROR IN DECRYPTION");
	for(int i=0; i<size; i++){
		data[i]=returnAux[i];
	}

	return ret;
}