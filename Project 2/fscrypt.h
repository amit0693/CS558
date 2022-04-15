/* Header guards */
#ifndef __FSCRYPT_H
#define __FSCRYPT_H


#include "openssl/blowfish.h"

// Block size for blowfish
#define BLOCKSIZE 8

/*Helper function that does XORing. */
void xor_bytes(unsigned char* res, unsigned char *a, unsigned char *b, uint32_t size); 

/*** The following functions implement Blowfish CBC using the BF_ecb_encrypt() and BF_set_key() functions. 
     * The CBC mode, is implemented from scratch * 

****/


// encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);

// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);


/*** The following functions implement Blowfish CBC using the BF_cbc_encrypt() and BF_set_key() functions. ****/

// encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt2(void *plaintext, int bufsize, char *keystr, int *resultlen);

// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt2(void *ciphertext, int bufsize, char *keystr, int *resultlen);


#endif
