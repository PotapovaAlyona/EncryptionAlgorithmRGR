#include "playfair.h"

// Внешние функции из playfair_matrix.cpp
extern void build_matrix_export(const unsigned char* key, size_t key_len);
extern void prepare_text_export(const unsigned char* input, size_t size, unsigned char* output, size_t* out_size);
extern void encrypt_pair_export(unsigned char a, unsigned char b, unsigned char* ra, unsigned char* rb);

// Шифрование Плейфера
int playfair_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    // Проверка параметров
    if (!key.data || key.size == 0) return CRYPT_ERR_KEY;
    if (!input.data || input.size == 0) return CRYPT_ERR_INPUT;
    if (!output || !output->data || output->size == 0) return CRYPT_ERR_OUTPUT;
    
    unsigned char prepared[2048];
    size_t prep_size = 0;
    
    // Построение матрицы из ключа
    build_matrix_export(key.data, key.size);
    // Подготовка текста (удаление не-букв, J->I, добавление X)
    prepare_text_export(input.data, input.size, prepared, &prep_size);
    
    if (output->size < prep_size) return CRYPT_ERR_OUTPUT;
    
    // Шифрование пар символов
    for (size_t i = 0; i < prep_size; i += 2) {
        encrypt_pair_export(prepared[i], prepared[i + 1], 
                            &output->data[i], &output->data[i + 1]);
    }
    
    output->size = prep_size;
    return CRYPT_OK;
}
