#include "vigenere.h"

// Возвращает имя шифра
const char* vigenere_get_name(void) {
    return "Vigenere Cipher";
}

// Возвращает размер ключа (0 = ключ переменной длины)
size_t vigenere_get_key_size(void) {
    return 0;
}

// Возвращает размер выходных данных (для Виженера = входным)
size_t vigenere_get_output_size(size_t input_size, int mode) {
    (void)mode;  // параметр не используется
    return input_size;
}
