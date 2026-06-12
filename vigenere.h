#ifndef VIGENERE_H
#define VIGENERE_H

#include "buffer.h"
#include "error_codes.h"

// Интерфейс шифра Виженера
const char* vigenere_get_name(void); // имя шифра
size_t vigenere_get_key_size(void); // размер ключа (0 = переменный)
size_t vigenere_get_output_size(size_t input_size, int mode); // размер выходных данных
int vigenere_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // шифрование
int vigenere_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // дешифрование

#endif
