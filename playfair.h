#ifndef PLAYFAIR_H
#define PLAYFAIR_H

#include "buffer.h"
#include "error_codes.h"

const char* playfair_get_name(void);
size_t playfair_get_key_size(void);
size_t playfair_get_output_size(size_t input_size, int mode);
int playfair_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
int playfair_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

#endif
