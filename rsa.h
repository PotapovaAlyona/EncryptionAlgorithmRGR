#ifndef RSA_H
#define RSA_H
#include "buffer.h"
#include "error_codes.h"
// Интерфейс шифра RSA
const char* rsa_get_name(void);                          // имя шифра
size_t rsa_get_key_size(void);                           // размер ключа
size_t rsa_get_output_size(size_t input_size, int mode); // размер выходных данных
int rsa_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // шифрование
int rsa_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output); // дешифрование
int rsa_generate_keys(unsigned int* n, unsigned int* e, unsigned int* d); // генерация ключей
#endif
