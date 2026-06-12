#ifndef VIGENERE_H
#define VIGENERE_H

#include "buffer.h"
#include "error_codes.h"

const char* vigenere_get_name(void);
size_t vigenere_get_key_size(void);
size_t vigenere_get_output_size(size_t input_size, int mode);
int vigenere_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
int vigenere_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

#endif
