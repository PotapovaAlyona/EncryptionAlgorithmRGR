#ifndef PLAYFAIR_H
#define PLAYFAIR_H

#include "buffer.h"
#include "error_codes.h"

// Интерфейс шифра Плейфера
const char* playfair_get_name(void); // имя шифра
size_t playfair_get_key_size(void);  // размер ключа 
size_t playfair_get_output_size(size_t input_size, int mode); // размер вых данных
int playfair_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // шифрование
int playfair_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // дешифрование

#endif
