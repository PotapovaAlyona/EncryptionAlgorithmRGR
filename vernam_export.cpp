#include "vernam.h"
// Экспорт для динамической библиотеки#ifdef _WIN32
    #define EXPORT __declspec(dllexport)   // Windows
#else
    #define EXPORT __attribute__((visibility("default")))  // Linux
#endif
extern "C" {  // Отключаем C++ name mangling
EXPORT const char* vernam_get_name_export(void) {
    return vernam_get_name();
}
EXPORT size_t vernam_get_key_size_export(void) {
    return vernam_get_key_size();
}
EXPORT size_t vernam_get_output_size_export(size_t input_size, int mode) {
    return vernam_get_output_size(input_size, mode);
}
EXPORT int vernam_encrypt_export(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return vernam_encrypt(key, input, output);
}
EXPORT int vernam_decrypt_export(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return vernam_decrypt(key, input, output);
}
}

