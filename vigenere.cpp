#include "vigenere.h"

const char* vigenere_get_name(void) {
    return "Vigenere Cipher";
}

size_t vigenere_get_key_size(void) {
    return 0;
}

size_t vigenere_get_output_size(size_t input_size, int mode) {
    (void)mode;
    return input_size;
}
