/**************************
   Implementation file, for 
   Blowfish in CBC mode using OpenSSL API
   
 * Here CBC mode, encryption is implemented from scratch * 
****************************/

/*We include the "blowfish.h" header from OpenSSL, which contains,
all the APIs we need to implement,
Blowfish. */
#include <openssl/blowfish.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "fscrypt.h"

/*
    We create, a helper function xor_bytes(): This will XOR two unsigned char arrays of 'size' bytes. The result, will be in 'res'
    
    Here in our case: 
    res[i] = a[i] ^ b[i]; 0 <= i < size; 
*/

void xor_bytes(unsigned char *res, unsigned char *a, unsigned char *b, uint32_t size)
{
	for (int i = 0; i < size; i++)
	{
		res[i] = a[i] ^ b[i];
	}
}

/*
  *This functions encrypts plaintext of size bufsize using "keystr" and it returns the ciphertext. 
  *The length of the result will always be an integral multiple of 8 bytes and will be stored in the variable pointed to by "resultlen"
 
  * If "bufsize" is not an integral multiple of 8 bytes, we padd the required number of null bytes. All this is done in a heap allocated buffer that is local to the function. 
*/
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen)
{
	unsigned char *ciphertext = NULL;

	/*A simple safety check. */
	if (plaintext == NULL)
	{
		(*resultlen) = 0;
		return ciphertext;
	}

	// First we need to find out the number of times we need to call BF_ecb_encrypt();
	uint32_t n = bufsize / BLOCKSIZE;	// Division by BLOCKSIZE.
	uint32_t rem = bufsize % BLOCKSIZE; // Remaining bytes.
	uint32_t padding_size = 0;			// Size in bytes of padding to be applied.

	if (rem > 0)
	{
		// We need to apply padding.
		padding_size = BLOCKSIZE - rem;

		// Because of this padding we need to do BF_ecb_encrypt() one more time.
		n++;
	}

	unsigned char *message = (unsigned char *)malloc((bufsize + padding_size));

	// We also allocate memory for the resulting ciphertext.

	ciphertext = (unsigned char *)malloc((bufsize + padding_size));

	// Now we zero out all the elements of the array message, as well as ciphertext.
	memset(message, 0x00, (bufsize + padding_size));
	memset(ciphertext, 0x00, (bufsize + padding_size));

	// Now we copy the plaintext into the message.
	memcpy(message, plaintext, bufsize);

	// This is our initialization vector IV, all set to zero.
	unsigned char IV[BLOCKSIZE];
	memset(IV, 0x00, BLOCKSIZE);

	uint32_t c = 0; // Counter

	// First we set up the key for the encryption.
	BF_KEY bfkey;

	BF_set_key(&bfkey, strlen(keystr), (unsigned char *)keystr);

	unsigned char *to_xor = IV; // For the first block of 8 bytes, we will XOR with IV.

	while (c < n)
	{
		// We encrypt the data in 8 byte blocks.
		// First we XOR previous ciphertext with message.
		xor_bytes(message + c * BLOCKSIZE, message + c * BLOCKSIZE, to_xor, BLOCKSIZE);

		BF_ecb_encrypt(message + c * BLOCKSIZE, ciphertext + c * BLOCKSIZE, &bfkey, BF_ENCRYPT);

		to_xor = ciphertext + c * BLOCKSIZE;
		c++;
	}
	
	free(message); // Since we allocated that for the sake of this function only. 

	*resultlen = bufsize + padding_size;
	return ciphertext;
}

/*
  * This function decrypts the ciphertext of size "bufsize", which is always going to be an integral multiple of 8. The decrypted ciphertext (plaintext is returned). 
  
  * If the input "bufsize" is not an integral multiple of 8 bytes, the function will report an error. 
  
  * The variable pointed to by "resultlen" will contain the size of the plaintext + size of padding if any that was originally applied. 

*/
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen)
{
	// This is our decryption function.

	unsigned char *plaintext = NULL;
	// A simple check.
	if (ciphertext == NULL)
	{
		(*resultlen) = 0;
		return plaintext;
	}

	// We print an error if our input data to decrypt is not an integral multiple of eight, which should be.
	if ((bufsize % 8) != 0)
	{
		printf("\n[!]ERROR: The data to decrypt has size that is not a multiple of 8. \n    Some data is missing, decryption failed! \n");
		(*resultlen) = 0;
		return plaintext;
	}
	
	// We calculate the number of times, the BF_ecb_encrypt() function needs to be run in decryption mode, to decrypt the message. 
	
	uint32_t n = bufsize / BLOCKSIZE; 
	
	uint32_t c = 0; // Counter variable. 
	
	// We set up the key. 
	
	BF_KEY key; 
	BF_set_key(&key, strlen(keystr), (unsigned char *)keystr); 
	
	// This was our initialization vector IV, all set to zero.
	unsigned char IV[BLOCKSIZE];
	memset(IV, 0x00, BLOCKSIZE);
	
	// We dynamically allocate space to store our plaintext. 
	plaintext = (unsigned char*)malloc(bufsize); 
	memset(plaintext, 0x00, bufsize); 
	
	unsigned char *to_xor = IV; 
	// To decrypt the first block, we have to finally XOR it with the result of decryption using BF_ecb_encrypt()
	
	
	while(c < n)
	{
		// First we apply the decryption mode of the function. 
		BF_ecb_encrypt(ciphertext + c * BLOCKSIZE, plaintext + c * BLOCKSIZE, &key, BF_DECRYPT); 
		
		// To get the actual plaintext we need to do an XOR with the previous ciphertext block / IV
		
		xor_bytes(plaintext + c*BLOCKSIZE, plaintext + c * BLOCKSIZE, to_xor, BLOCKSIZE); 
		
		to_xor = ciphertext + c * BLOCKSIZE; 
		
		c++; // Counter incremented. 
	}
	
	/*We assume that these functions are decrypting data to get C-strings in the end. 
	  So we remove any padding (trailing null bytes) at the end, but keep the null byte that occurs before the non-null byte at the end, because C strings require a null terminator at the end!!!
	*/
	
	int tz = 0;  // Trailing zero counter. ; 
	for(int i = bufsize-1; i >= 0; i--)
	{
		if(plaintext[i] == 0)
		  tz++;
		else
		  break; // Non null byte found - break the loop. 
	}
	
	(*resultlen) = bufsize - tz + 1; 
	return plaintext; 
}

/*****END OF IMPLEMENTATION *******/