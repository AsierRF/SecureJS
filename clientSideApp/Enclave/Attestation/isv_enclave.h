#ifndef _ISV_ENCLAVE_H
#define _ISV_ENCLAVE_H

// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
//uint8_t * getSecretValue();

int doPublicKeyTask(uint8_t * secret);

#endif