#include "playfair.h"
#include <cstring>

static unsigned char matrix[5][5];

static int is_letter(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static unsigned char to_upper(unsigned char c) {
    if (c >= 'a' && c <= 'z') return c - 32;
    return c;
}

static int char_exists(const unsigned char* arr, size_t len, unsigned char c) {
    for (size_t i = 0; i < len; i++) {
        if (arr[i] == c) return 1;
    }
    return 0;
}

static void remove_char(unsigned char* arr, size_t* len, unsigned char c) {
    for (size_t i = 0; i < *len; i++) {
        if (arr[i] == c) {
            for (size_t j = i; j < *len - 1; j++) {
                arr[j] = arr[j + 1];
            }
            (*len)--;
            return;
        }
    }
}

static void build_matrix(const unsigned char* key, size_t key_len) {
    unsigned char alphabet[] = {'A','B','C','D','E','F','G','H','I','K','L','M',
                                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
    size_t alphabet_len = 25;
    
    unsigned char combined[25];
    size_t combined_len = 0;
    
    unsigned char full[25];
    size_t full_len = 0;
    
    for (size_t i = 0; i < key_len; i++) {
        unsigned char c = to_upper(key[i]);
        if (c == 'J') c = 'I';
        if (is_letter(c)) {
            if (!char_exists(combined, combined_len, c)) {
                combined[combined_len] = c;
                combined_len++;
            }
        }
    }
    
    for (size_t i = 0; i < combined_len; i++) {
        full[full_len] = combined[i];
        full_len++;
        remove_char(alphabet, &alphabet_len, combined[i]);
    }
    
    for (size_t i = 0; i < alphabet_len; i++) {
        full[full_len] = alphabet[i];
        full_len++;
    }
    
    for (int row = 0; row < 5; row++) {
        for (int col = 0; col < 5; col++) {
            matrix[row][col] = full[row * 5 + col];
        }
    }
}

static void find_position(unsigned char c, int* row, int* col) {
    c = to_upper(c);
    if (c == 'J') c = 'I';
    
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            if (matrix[i][j] == c) {
                *row = i;
                *col = j;
                return;
            }
        }
    }
}

static void prepare_text(const unsigned char* input, size_t size, unsigned char* output, size_t* out_size) {
    unsigned char temp[1024];
    size_t temp_len = 0;
    
    for (size_t i = 0; i < size; i++) {
        unsigned char c = to_upper(input[i]);
        if (c == 'J') c = 'I';
        if (is_letter(c)) {
            temp[temp_len] = c;
            temp_len++;
        }
    }
    
    *out_size = 0;
    for (size_t i = 0; i < temp_len; i++) {
        output[*out_size] = temp[i];
        (*out_size)++;
        
        if (i + 1 < temp_len && temp[i] == temp[i + 1]) {
            output[*out_size] = 'X';
            (*out_size)++;
        }
    }
    
    if (*out_size % 2 != 0) {
        output[*out_size] = 'X';
        (*out_size)++;
    }
}

static void encrypt_pair(unsigned char a, unsigned char b, unsigned char* ra, unsigned char* rb) {
    int r1, c1, r2, c2;
    find_position(a, &r1, &c1);
    find_position(b, &r2, &c2);
    
    if (r1 == r2) {
        *ra = matrix[r1][(c1 + 1) % 5];
        *rb = matrix[r2][(c2 + 1) % 5];
    } else if (c1 == c2) {
        *ra = matrix[(r1 + 1) % 5][c1];
        *rb = matrix[(r2 + 1) % 5][c2];
    } else {
        *ra = matrix[r1][c2];
        *rb = matrix[r2][c1];
    }
}

static void decrypt_pair(unsigned char a, unsigned char b, unsigned char* ra, unsigned char* rb) {
    int r1, c1, r2, c2;
    find_position(a, &r1, &c1);
    find_position(b, &r2, &c2);
    
    if (r1 == r2) {
        *ra = matrix[r1][(c1 + 4) % 5];
        *rb = matrix[r2][(c2 + 4) % 5];
    } else if (c1 == c2) {
        *ra = matrix[(r1 + 4) % 5][c1];
        *rb = matrix[(r2 + 4) % 5][c2];
    } else {
        *ra = matrix[r1][c2];
        *rb = matrix[r2][c1];
    }
}

void build_matrix_export(const unsigned char* key, size_t key_len) {
    build_matrix(key, key_len);
}

void prepare_text_export(const unsigned char* input, size_t size, unsigned char* output, size_t* out_size) {
    prepare_text(input, size, output, out_size);
}

void encrypt_pair_export(unsigned char a, unsigned char b, unsigned char* ra, unsigned char* rb) {
    encrypt_pair(a, b, ra, rb);
}

void decrypt_pair_export(unsigned char a, unsigned char b, unsigned char* ra, unsigned char* rb) {
    decrypt_pair(a, b, ra, rb);
}
