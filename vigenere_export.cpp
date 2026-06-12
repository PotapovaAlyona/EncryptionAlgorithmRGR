#include "vigenere.h"

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

EXPORT const char* vigenere_get_name_export(void) {
    return vigenere_get_name();
}

EXPORT size_t vigenere_get_key_size_export(void) {
    return vigenere_get_key_size();
}

EXPORT size_t vigenere_get_output_size_export(size_t input_size, int mode) {
    return vigenere_get_output_size(input_size, mode);
}

EXPORT int vigenere_encrypt_export(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return vigenere_encrypt(key, input, output);
}

EXPORT int vigenere_decrypt_export(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return vigenere_decrypt(key, input, output);
}

}
