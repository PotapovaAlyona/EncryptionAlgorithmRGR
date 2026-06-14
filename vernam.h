#ifndef VERNAM_H
#define VERNAM_H
#include "buffer.h"
#include "error_codes.h"
// Интерфейс шифра Вернам (XOR)
const char* vernam_get_name(void);                          // имя шифра
size_t vernam_get_key_size(void);                           // размер ключа (0 = переменный)
size_t vernam_get_output_size(size_t input_size, int mode); // размер выходных данных
int vernam_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // шифрование
int vernam_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // дешифрование
#endif
