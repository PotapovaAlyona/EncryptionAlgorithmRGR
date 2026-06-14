#include "vernam.h"
// Возвращает имя шифра
const char* vernam_get_name(void) {
    return "Vernam Cipher (XOR)";
}
// Возвращает размер ключа (0 = ключ переменной длины)
size_t vernam_get_key_size(void) {
    return 0;
}
// Возвращает размер выходных данных (для Вернама = входным)
size_t vernam_get_output_size(size_t input_size, int mode) {
    return input_size;
}
