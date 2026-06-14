#include "vernam.h"
// Дешифрование Вернам (XOR - то же самое что шифрование)
int vernam_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
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
    
    // XOR расшифровка (обратима, поэтому код как у шифрования)
    for (size_t i = 0; i < input.size; ++i) {
        unsigned char k = key.data
[i % key.size];
        output->data[i] = input.data
[i] ^ k;
    }
    
    output->size = input.size;
    return CRYPT_OK;
}
