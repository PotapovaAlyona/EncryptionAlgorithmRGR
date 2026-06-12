#include "playfair.h"

// Экспорт для динамической библиотеки
#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

extern "C" {  // Отключаем C++ name mangling

EXPORT const char* playfair_get_name_export(void) {
    return playfair_get_name();
}

EXPORT size_t playfair_get_key_size_export(void) {
    return playfair_get_key_size();
}

EXPORT size_t playfair_get_output_size_export(size_t input_size, int mode) {
    return playfair_get_output_size(input_size, mode);
}

EXPORT int playfair_encrypt_export(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return playfair_encrypt(key, input, output);
}

EXPORT int playfair_decrypt_export(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return playfair_decrypt(key, input, output);
}

}
