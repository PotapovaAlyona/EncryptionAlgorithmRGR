#include "vigenere.h"

int vigenere_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || key.size == 0) return CRYPT_ERR_KEY;
    if (!input.data || input.size == 0) return CRYPT_ERR_INPUT;
    if (!output || !output->data || output->size == 0) return CRYPT_ERR_OUTPUT;
    if (output->size < input.size) return CRYPT_ERR_OUTPUT;
    
    for (size_t i = 0; i < input.size; i++) {
        unsigned char k = key.data[i % key.size];
        output->data[i] = (input.data[i] + k) % 256;
    }
    
    output->size = input.size;
    return CRYPT_OK;
}
