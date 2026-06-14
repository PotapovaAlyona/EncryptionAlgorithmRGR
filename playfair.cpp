#include "playfair.h"

//возвр имя шифра
const char* playfair_get_name(void) {
    return "Playfair Cipher";
}

//возвр размер ключа
size_t playfair_get_key_size(void) {
    return 0;
}

//возвр размер вых дан
size_t playfair_get_output_size(size_t input_size, int mode) {
    (void)mode;
    return input_size * 2;
}
