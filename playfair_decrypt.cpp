#include "playfair.h"

// Внешние функции из playfair_matrix.cpp
extern void build_matrix_export(const unsigned char* key, size_t key_len);
extern void decrypt_pair_export(unsigned char a, unsigned char b, unsigned char* ra, unsigned char* rb);

// Дешифрование Плейфера
int playfair_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка параметров
    if (!key.data || key.size == 0) return CRYPT_ERR_KEY;
    if (!input.data || input.size == 0 || input.size % 2 != 0) return CRYPT_ERR_INPUT;
    if (!output || !output->data || output->size == 0) return CRYPT_ERR_OUTPUT;
    if (output->size < input.size) return CRYPT_ERR_OUTPUT;
    
    // Построение матрицы из ключа
    build_matrix_export(key.data, key.size);
    
    // Дешифрование пар символов
    for (size_t i = 0; i < input.size; i += 2) {
        decrypt_pair_export(input.data[i], input.data[i + 1], 
                            &output->data[i], &output->data[i + 1]);
    }
    
    // Удаление добавленных символов 'X' в конце
    size_t out_size = input.size;
    while (out_size > 0 && output->data[out_size - 1] == 'X') {
        out_size--;
    }
    
    output->size = out_size;
    return CRYPT_OK;
}
