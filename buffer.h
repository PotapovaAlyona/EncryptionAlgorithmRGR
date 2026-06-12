#ifndef BUFFER_H
#define BUFFER_H

#include <cstddef>

// Структ для вход данных (только чтение)
struct ConstBuffer {
    const unsigned char* data;  // указатель на данные
    size_t size;                // размер данных
};

// Структ для вых данных (чтение/запись)
struct MutBuffer {
    unsigned char* data;        // указатель на буфер
    size_t size;                // размер буфера
};

#endif
