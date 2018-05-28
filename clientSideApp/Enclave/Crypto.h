#ifndef _SIGNATURE_H
#define _SIGNATURE_H

#include "sgx_tcrypto.h"
#include <string.h>
#include <string>
#include <vector>

bool setEncrypted();
bool isEncrypted ();
int setJavaScriptPublicKey(sgx_ec256_public_t * newPublicKey);
int setJavaScriptEncryptionKey(sgx_aes_gcm_128bit_key_t newEncryptionKey);
sgx_ec256_public_t * getMyPublicKey ();
sgx_aes_gcm_128bit_key_t * getMyEncryptionKey ();
int generateKeys();
int signData(std::string stringValue, sgx_ec256_signature_t * output);
int checkSignature(std::string stringValue, sgx_ec256_signature_t * p_signature_to_check);
int decryptSecret(std::vector <uint8_t> functionHexEncrypted, int functionHex_size, uint8_t mac [16], std::vector <uint8_t> * functionHexDecrypted);
int encryptPlaintext(std::vector <uint8_t> textHexDecrypted, std::vector <uint8_t> * textHexEncrypted);

#endif