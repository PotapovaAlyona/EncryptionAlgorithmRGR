#include "vigenere.h"

int vigenere_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || key.size == 0) return CRYPT_ERR_KEY;
    if (!input.data || input.size == 0) return CRYPT_ERR_INPUT;
    if (!output || !output->data || output->size == 0) return CRYPT_ERR_OUTPUT;
    if (output->size < input.size) return CRYPT_ERR_OUTPUT;
    
    for (size_t i = 0; i < input.size; i++) {
        unsigned char k = key.data[i % key.size];
        int temp = (int)input.data[i] - (int)k;
        if (temp < 0) temp += 256;
        output->data[i] = (unsigned char)temp;
    }
    
    output->size = input.size;
    return CRYPT_OK;
}
