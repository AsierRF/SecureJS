/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <assert.h>
#include "../Enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "isv_enclave.h"
#include "../Enclave.h"
#include "../Crypto.h"

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }sha
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    bool derive_ret = false;

    if (NULL == shared_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ISV_KDF_ID != kdf_id)
    {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
        return SGX_ERROR_KDF_MISMATCH;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
        smk_key, sk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
        mk_key, vk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse)
    {
        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse)
    {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}


/*PUT SECRET DATA ENCRYPTION KEY*/
/*
    Given the encrypted message from the service provide, it decrypts the values, 
    store them and generate the encrypted value to be sent to the Service Provider in Encryption Mode.
    Input:  sgx_ra_context_t context -> context required to get the ECDH key
            uint8_t *p_secret -> pointer to the secret received from the Service Provider
            uint32_t secret_size -> size of the p_secret
            uint8_t *p_gcm_mac -> pointer to the MAC value generated in the encryption
    Output: sgx_status_t -> Enclave status, depending on whether errors occurred during the execution or not
            uint8_t* secret_for_server -> pointer to the secret returned to be sent to the Service Provider
            uint8_t* mac_for_server -> pointer to the MAC generated in the encryption of the secret to be sent to the Service Provider
*/
sgx_status_t put_secret_data_encryptionKey(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac,
    uint8_t* secret_for_server,
    uint8_t* mac_for_server)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
    int retValue = 0;
    do {
        if(secret_size == 0)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        
        if(!setEncrypted()) return SGX_ERROR_UNEXPECTED;
        uint8_t aes_gcm_iv[12] = {0};
        uint8_t * secret =new uint8_t [secret_size];
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         &secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)
                                            (p_gcm_mac));
        sgx_aes_gcm_128bit_key_t encryptedJSkey = {0};
        /*Do Public key task*/
        retValue = doPublicKeyTask(secret);
        if(retValue==0)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        else if(retValue==-1)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        /*Get client's public key*/
        sgx_ec256_public_t * publicKeyToEncrypt = getMyPublicKey();
        if(publicKeyToEncrypt==NULL)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        /*Do Encryption Key task*/
        for(int i=0; i<16; i++){
            encryptedJSkey[i]=secret[i+64];
        }
        retValue = setJavaScriptEncryptionKey(encryptedJSkey);
        if(retValue == 0) 
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        sgx_aes_gcm_128bit_key_t * keyToEncrypt = getMyEncryptionKey();
        uint32_t toEncrypt_len = 80;
        uint8_t toEncrypt [toEncrypt_len] = {0};
        for(int i=0; i<32; i++){
            toEncrypt[i]=publicKeyToEncrypt->gx[i];
            toEncrypt[i+32]=publicKeyToEncrypt->gy[i];
        }
        for(int i=0; i<16; i++){
            toEncrypt[i+64]=(*keyToEncrypt)[i];
        }
        /*Encrypt the array*/
        uint8_t mac_aux [16] = {0};
        ret = sgx_rijndael128GCM_encrypt(&sk_key,
                        toEncrypt,
                        toEncrypt_len,
                        secret_for_server,
                        &aes_gcm_iv[0],
                        12,
                        NULL,
                        0,
                        &mac_aux);
        for(int i=0; i<16;i++){
            mac_for_server[i]=mac_aux[i];
        }
    } while(0);
    return ret;
}

/*PUT SECRET DATA PUBLIC KEY*/
/*
    Given the encrypted message from the service provide, it decrypts the values, 
    store them and generate the encrypted value to be sent to the Service Provider in Signature Mode.
    Input:  sgx_ra_context_t context -> context required to get the ECDH key
            uint8_t *p_secret -> pointer to the secret received from the Service Provider
            uint32_t secret_size -> size of the p_secret
            uint8_t *p_gcm_mac -> pointer to the MAC value generated in the encryption
    Output: sgx_status_t -> Enclave status, depending on whether errors occurred during the execution or not
            uint8_t* secret_for_server -> pointer to the secret returned to be sent to the Service Provider
            uint8_t* mac_for_server -> pointer to the MAC generated in the encryption of the secret to be sent to the Service Provider
*/
sgx_status_t put_secret_data_publicKey(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac,
    uint8_t* secret_for_server,
    uint8_t* mac_for_server)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
    int retValue = 0;
    do {
        if(secret_size == 0)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }

        uint8_t aes_gcm_iv[12] = {0};
        uint8_t * secret =new uint8_t [secret_size];
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         &secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)
                                            (p_gcm_mac));
        retValue = doPublicKeyTask(secret);
        if(retValue==0)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        else if(retValue==-1)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        /*Get client's public key*/
        sgx_ec256_public_t * keyToEncrypt = getMyPublicKey();
        if(keyToEncrypt==NULL)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }
        /*Add it to an encryptable array*/
        uint32_t toEncrypt_len = 64;
        uint8_t toEncrypt [64] = {0};
        for(int i=0; i< 32; i++){
            toEncrypt[i]=keyToEncrypt->gx[i];
            toEncrypt[i+32]=keyToEncrypt->gy[i];
        }
        /*Encrypt the array*/
        uint8_t mac_aux [16] = {0};
        ret = sgx_rijndael128GCM_encrypt(&sk_key,
                        toEncrypt,
                        toEncrypt_len,
                        secret_for_server,
                        &aes_gcm_iv[0],
                        12,
                        NULL,
                        0,
                        &mac_aux);
        for(int i=0; i<16;i++){
            mac_for_server[i]=mac_aux[i];
        }

    } while(0);
    return ret;
}

/*DO PUBLIC KEY TASK*/
/*
    Given the decrypted value that includes the Public key of the Service Provider,
        store the that Public Key and generate the platform's Public key
    Input:  sgx_ra_context_t context -> context required to get the ECDH key
            uint8_t *p_secret -> pointer to the secret received from the Service Provider
            uint32_t secret_size -> size of the p_secret
            uint8_t *p_gcm_mac -> pointer to the MAC value generated in the encryption
    Output: int -> 1 if correct, 0 or -1 if incorrect
*/
int doPublicKeyTask(uint8_t * secret)
{
    int retValue=0;
    sgx_ec256_public_t * js_public = new (sgx_ec256_public_t);
    for(int i=0; i<( sizeof(js_public->gx)/sizeof(js_public->gx[0]) ); i++){
        /*The secret key's two parts has been added into one array 
        [half 1 (i = 0->31, half 2 (i = 32 -> 63, == i+32)] (half 1 = gx, half 2 = gy)*/
        js_public->gx[i]=secret[i];
        js_public->gy[i]=secret[i+32];
    }
    //Add the key in the Crypto.cpp memory variable
    retValue = setJavaScriptPublicKey(js_public);
    if(retValue == 0) 
    {
        return 0;
    }
    /*Generate keys for the client*/
    retValue = generateKeys();
    if(retValue == 0) 
    {
        return 0;
    }
    else if(retValue == -1)
    { 
        return -1;
    }
    return 1;
}