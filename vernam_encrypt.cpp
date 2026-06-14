#include "vernam.h"
// Шифрование Вернам (XOR)
int vernam_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка ключа
    if (key.data
 == 0) return CRYPT_ERR_KEY;
    if (key.size == 0) return CRYPT_ERR_KEY;
    
    // Проверка входных данных
    if (input.data
 == 0) return CRYPT_ERR_INPUT;
    if (input.size == 0) return CRYPT_ERR_INPUT;
    
    // Проверка выходного буфера
    if (output == 0) return CRYPT_ERR_OUTPUT;
    if (output->data == 0) return CRYPT_ERR_OUTPUT;
    if (output->size == 0) return CRYPT_ERR_OUTPUT;
    if (output->size < input.size) return CRYPT_ERR_OUTPUT;
    
    // XOR шифрование: каждый байт ^ с байтом ключа
    for (size_t i = 0; i < input.size; ++i) {
        unsigned char k = key.data
[i % key.size];  // циклический ключ
        output->data[i] = input.data
[i] ^ k;       // XOR операция
    }
    
    output->size = input.size;
    return CRYPT_OK;
}
