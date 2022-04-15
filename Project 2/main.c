#include "fscrypt.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  // USAGE:
  // $ exec [plaintext] [keytext]
  // Enclose plaintext and keytext with " " in case the text contains spaces.

  char* s = argv[1];
  char* pass = argv[2];
  char *outbuf, *recvbuf;
  int len = 0;
  int recvlen = 0;

  // Encrypt s using pass as key.
  outbuf = (char *)fs_encrypt((void *)s, strlen(s) + 1, pass, &len);
  printf("%s %d\n", "length after encryption = ", len);

  // Print the resulting ciphertext
  int i = 0;
  printf("ciphertext = ");
  for (i = 0; i < len; i++)
    printf("%02x", (unsigned char)outbuf[i]);
  printf("\n");

  // Decrypt the ciphertext
  recvbuf = (char *)fs_decrypt((void *)outbuf, len, pass, &recvlen);

  // Assert the decrypted text equals the original text,
  // and print it to console.
  assert(memcmp(s, recvbuf, recvlen) == 0);
  assert(recvlen == (strlen(s) + 1));
  printf("plaintext = %s\n", recvbuf);

  // Caller frees memory allocated by the encryption/decryption functions
  free(outbuf);
  free(recvbuf);

  return 0;
}
