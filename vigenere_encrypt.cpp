#include "vigenere.h"

// Шифрование Виженера
int vigenere_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка ключа
    if (!key.data || key.size == 0) return CRYPT_ERR_KEY;
    // Проверка входных данных
    if (!input.data || input.size == 0) return CRYPT_ERR_INPUT;
    // Проверка выходного буфера
    if (!output || !output->data || output->size == 0) return CRYPT_ERR_OUTPUT;
    if (output->size < input.size) return CRYPT_ERR_OUTPUT;
    
    // Шифрование каждого байта
    for (size_t i = 0; i < input.size; i++) {
        unsigned char k = key.data[i % key.size];// байт ключа (циклически)
        output->data[i] = (input.data[i] + k) % 256; // сложение по модулю 256
    }
    
    output->size = input.size;
    return CRYPT_OK;
}
