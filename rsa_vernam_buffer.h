#ifndef BUFFER_H
#define BUFFER_H
#include <cstddef>
// Структура для входных данных (только чтение)
struct ConstBuffer {
    const unsigned char* data;  // указатель на данные
    size_t size;                // размер данных
};
// Структура для выходных данных (чтение/запись)
struct MutBuffer {
    unsigned char* data;        // указатель на буфер
    size_t size;                // размер буфера
};
#endif
