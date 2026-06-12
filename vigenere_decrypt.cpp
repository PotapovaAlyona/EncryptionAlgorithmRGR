#include "vigenere.h"

// Дешифрование Виженера: P = (C - K + 256) mod 256
int vigenere_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка ключа
    if (!key.data || key.size == 0) return CRYPT_ERR_KEY;
    // Проверка входных данных
    if (!input.data || input.size == 0) return CRYPT_ERR_INPUT;
    // Проверка выходного буфера
    if (!output || !output->data || output->size == 0) return CRYPT_ERR_OUTPUT;
    if (output->size < input.size) return CRYPT_ERR_OUTPUT;
    
    // Дешифрование каждого байта
    for (size_t i = 0; i < input.size; i++) {
        unsigned char k = key.data[i % key.size]; // байт ключа
        int temp = (int)input.data[i] - (int)k;   // вычитание
        if (temp < 0) temp += 256;  // коррекция отрицательных
        output->data[i] = (unsigned char)temp;
    }
    
    output->size = input.size;
    return CRYPT_OK;
}
