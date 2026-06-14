#include "rsa.h"
// Быстрое возведение в степень по модулю
static unsigned int mod_pow_uint(unsigned int base, unsigned int exp, unsigned int mod) {
    unsigned int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2;
    }
    return result;
}
// RSA шифрование: c = m^e mod n
int rsa_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка входных данных
    if (input.data
 == 0) return CRYPT_ERR_INPUT;
    if (input.size == 0) return CRYPT_ERR_INPUT;
    
    // Проверка выходного буфера
    if (output == 0) return CRYPT_ERR_OUTPUT;
    if (output->data == 0) return CRYPT_ERR_OUTPUT;
    if (output->size == 0) return CRYPT_ERR_OUTPUT;
    
    // Извлечение ключа из буфера (n - 4 байта, e - 4 байта)
    unsigned int n = 0;
    unsigned int e = 0;
    
    if (key.data
 != 0 && key.size >= 8) {
        for (size_t i = 0; i < 4 && i < key.size; ++i) {
            n = n * 256 + key.data
[i];
        }
        for (size_t i = 4; i < 8 && i < key.size; ++i) {
            e = e * 256 + key.data
[i];
        }
    } else {
        return CRYPT_ERR_KEY;
    }
    
    if (n == 0) return CRYPT_ERR_KEY;
    if (e == 0) return CRYPT_ERR_KEY;
    
    // Размер блока в байтах (зависит от n)
    size_t block_size = 0;
    unsigned int temp_n = n;
    while (temp_n > 0) {
        block_size = block_size + 1;
        temp_n = temp_n / 256;
    }
    
    if (output->size < input.size * block_size) return CRYPT_ERR_OUTPUT;
    
    // Шифрование каждого байта
    size_t out_pos = 0;
    for (size_t i = 0; i < input.size; ++i) {
        unsigned int m = input.data
[i];
        unsigned int c = mod_pow_uint(m, e, n);  // c = m^e mod n
        
        // Запись шифроблока в выходной буфер
        for (int shift = (block_size - 1) * 8; shift >= 0; shift = shift - 8) {
            output->data[out_pos] = (c >> shift) & 255;
            out_pos = out_pos + 1;
        }
    }
    
    output->size = out_pos;
    return CRYPT_OK;
}

