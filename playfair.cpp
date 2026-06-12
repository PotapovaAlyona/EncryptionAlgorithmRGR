#include "playfair.h"

const char* playfair_get_name(void) {
    return "Playfair Cipher";
}

size_t playfair_get_key_size(void) {
    return 0;
}

size_t playfair_get_output_size(size_t input_size, int mode) {
    (void)mode;
    return input_size * 2;
}
