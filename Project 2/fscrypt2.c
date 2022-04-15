
#include <openssl/blowfish.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "fscrypt.h"


void *fs_encrypt2(void *plaintext, int bufsize, char *keystr, int *resultlen)
{
	unsigned char *ciphertext = NULL;

	/*A simple safety check. */
	if (plaintext == NULL)
	{
		(*resultlen) = 0;
		return ciphertext;
	}

	// First we calculate the size of the padding.
	uint32_t padding = BLOCKSIZE - (bufsize % BLOCKSIZE);

	// Now we allocate the required buffer, and memset every byte to zero.    // We calculate padding to allocate the size of the output buffer.

	ciphertext = (unsigned char *)malloc(bufsize + padding);

	// We set up the key.
	BF_KEY key;
	BF_set_key(&key, strlen(keystr), (unsigned char *)keystr);

	// This is our initialization vector IV, all set to zero.
	unsigned char IV[BLOCKSIZE];
	memset(IV, 0x00, BLOCKSIZE);

	/*BF_cbc_encrypt() can process the plaintext, irrespective of its length. */
	BF_cbc_encrypt((unsigned char *)plaintext, ciphertext, bufsize, &key, IV, BF_ENCRYPT); // Encryption mode. 

	(*resultlen) = (bufsize + padding);
	return ciphertext;
}


void *fs_decrypt2(void *ciphertext, int bufsize, char *keystr, int *resultlen)
{
	// This is our decryption function.

	unsigned char *plaintext = NULL;
	// A simple check.
	if (ciphertext == NULL)
	{
		(*resultlen) = 0;
		return plaintext;
	}

	// We allocate space for the plaintext.
	plaintext = (unsigned char *)malloc(bufsize);
	memset(plaintext, 0x00, bufsize);
	
	// We set up the key.
	BF_KEY key;
	
	BF_set_key(&key, strlen(keystr), (unsigned char *)keystr);

	// This was our initialization vector IV, all set to zero.
	unsigned char IV[BLOCKSIZE];
	memset(IV, 0x00, BLOCKSIZE);

	/*BF_cbc_encrypt() can process the ciphertext, irrespective of its length. */
	BF_cbc_encrypt((unsigned char *)ciphertext, plaintext, bufsize, &key, IV, BF_DECRYPT); // Decryption mode. 

	

	int tz = 0; // Trailing zero counter. ;
	for (int i = bufsize - 1; i >= 0; i--)
	{
		if (plaintext[i] == 0)
			tz++;
		else
			break; // Non null byte found - break the loop.
	}

	(*resultlen) = bufsize - tz + 1;
	return plaintext;
}
