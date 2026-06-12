#ifndef BUFFER_H
#define BUFFER_H

#include <cstddef>

struct ConstBuffer {
    const unsigned char* data;
    size_t size;
};

struct MutBuffer {
    unsigned char* data;
    size_t size;
};

#endif
