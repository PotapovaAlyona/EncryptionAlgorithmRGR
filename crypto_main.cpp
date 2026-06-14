#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <filesystem>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <limits>

#include "buffer.h"
#include "error_codes.h"

using namespace std;
namespace fs = filesystem;

// =ФУНКЦИИ ШИФРОВ =

// Виженер
const char* vigenere_get_name(void);
int vigenere_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
int vigenere_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

// Плейфер
const char* playfair_get_name(void);
int playfair_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
int playfair_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

// Вернам (XOR)
const char* vernam_get_name(void);
int vernam_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
int vernam_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

// RSA
const char* rsa_get_name(void);
int rsa_encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
int rsa_decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
int rsa_generate_keys(unsigned int* n, unsigned int* e, unsigned int* d);

// =ФУНКЦИИ

// Единственный пароль для доступа к программе
static const char* MASTER_PASSWORD = "admin123";

// Проверка, является ли символ печатным
int is_printable(unsigned char c) {
    return (c >= 32 && c <= 126);
}

// Вывод данных в шестнадцатеричном формате
void print_hex(const unsigned char* data, size_t size) {
    size_t i;
    for (i = 0; i < size; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// Очистка буфера ввода
void clear_input() {
    cin.clear();
    cin.ignore(10000, '\n');
}

// Сравнение строк
int str_equal(const char* a, const char* b) {
    size_t i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) return 0;
        i = i + 1;
    }
    return (a[i] == '\0' && b[i] == '\0');
}

// Вывод сообщения об ошибке по коду
void error_msg(int code) {
    cout << "\n[ОШИБКА] ";
    switch(code) {
        case CRYPT_ERR_KEY: cout << "неверный ключ"; break;
        case CRYPT_ERR_INPUT: cout << "ошибка ввода"; break;
        case CRYPT_ERR_OUTPUT: cout << "ошибка вывода"; break;
        case CRYPT_ERR_MEM: cout << "ошибка памяти"; break;
        case CRYPT_ERR_LIB: cout << "ошибка библиотеки"; break;
        case CRYPT_ERR_INVAL: cout << "неверные параметры"; break;
        case CRYPT_ERR_FILE: cout << "ошибка файла"; break;
        default: cout << "код " << code;
    }
    cout << endl;
}

// Генерация случайного ключа
void generate_key(char* key, size_t len) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(33, 126);
    size_t i;
    for (i = 0; i < len; i++) {
        key[i] = (char)dis(gen);
    }
}

// Преобразование HEX строки в массив байт
size_t hex_to_bytes(const char* hex, unsigned char* bytes, size_t max_bytes) {
    size_t i;
    size_t pos = 0;
    for (i = 0; hex[i] != '\0' && hex[i+1] != '\0' && pos < max_bytes; i = i + 2) {
        if (isxdigit(hex[i]) && isxdigit(hex[i+1])) {
            char hx[3];
            hx[0] = hex[i];
            hx[1] = hex[i+1];
            hx[2] = '\0';
            bytes[pos] = (unsigned char)strtol(hx, NULL, 16);
            pos = pos + 1;
        }
    }
    return pos;
}

// Чтение файла
int read_file(const char* path, vector<unsigned char>& data) {
    ifstream f(path, ios::binary);
    if (!f.is_open()) return 0;
    data.assign(istreambuf_iterator<char>(f), istreambuf_iterator<char>());
    return 1;
}

// Запись файла
int write_file(const char* path, const unsigned char* data, size_t size) {
    ofstream f(path, ios::binary);
    if (!f.is_open()) return 0;
    f.write((const char*)data, size);
    return 1;
}

// Создание директории
int create_dir(const char* path) {
    fs::path dir = fs::path(path).parent_path();
    if (!dir.empty() && !fs::exists(dir)) {
        return fs::create_directories(dir);
    }
    return 1;
}

// = АУТЕНТИФИКАЦИЯ =

int login() {
    char password[256];
    
    cout << "\n========================================\n";
    cout << "     КРИПТОГРАФИЧЕСКИЙ КАЛЬКУЛЯТОР     \n";
    cout << "========================================\n";
    cout << "\n--- АУТЕНТИФИКАЦИЯ ---\n";
    cout << "Введите пароль: ";
    cin.getline(password, 256);
    
    if (str_equal(password, MASTER_PASSWORD)) {
        cout << "\n[+] Доступ разрешен!\n";
        return 1;
    }
    
    cout << "\n[-] Неверный пароль!\n";
    return 0;
}

// = КЛЮЧИ ВИЖЕНЕРА =

int get_key_vigenere(char* key_buf, size_t buf_size, int hint) {
    char choice[16];
    cout << "\n1) Ввести вручную\n2) Загрузить из файла\n3) Сгенерировать\nВыбор: ";
    cin.getline(choice, 16);
    
    if (str_equal(choice, "2")) {
        char fname[256];
        cout << "Файл: ";
        cin.getline(fname, 256);
        ifstream file(fname, ios::binary);
        if (!file.is_open()) return 0;
        file.read(key_buf, buf_size - 1);
        key_buf[file.gcount()] = '\0';
        return 1;
    }
    
    if (str_equal(choice, "3")) {
        size_t len = (hint != 0) ? (size_t)hint : 16;
        generate_key(key_buf, len);
        key_buf[len] = '\0';
        cout << "Ключ: " << key_buf << "\nHEX: ";
        print_hex((unsigned char*)key_buf, len);
        cout << "Сохранить в файл? (y/n): ";
        char save[16];
        cin.getline(save, 16);
        if (str_equal(save, "y") || str_equal(save, "Y")) {
            char fname[256];
            cout << "Файл: ";
            cin.getline(fname, 256);
            ofstream(fname, ios::binary).write(key_buf, len);
            cout << "Сохранен\n";
        }
        return 1;
    }
    
    cout << "Ключ: ";
    cin.getline(key_buf, buf_size);
    return 1;
}

// = КЛЮЧИ ВЕРНАМ =

int get_key_vernam(char* key_buf, size_t buf_size) {
    char choice[16];
    cout << "\n1) Ввести вручную\n2) Загрузить из файла\n3) Сгенерировать\nВыбор: ";
    cin.getline(choice, 16);
    
    if (str_equal(choice, "2")) {
        char fname[256];
        cout << "Файл: ";
        cin.getline(fname, 256);
        ifstream file(fname, ios::binary);
        if (!file.is_open()) return 0;
        file.read(key_buf, buf_size - 1);
        key_buf[file.gcount()] = '\0';
        return 1;
    }
    
    if (str_equal(choice, "3")) {
        generate_key(key_buf, 16);
        key_buf[16] = '\0';
        cout << "Ключ: " << key_buf << "\nHEX: ";
        print_hex((unsigned char*)key_buf, 16);
        cout << "Сохранить в файл? (y/n): ";
        char save[16];
        cin.getline(save, 16);
        if (str_equal(save, "y") || str_equal(save, "Y")) {
            char fname[256];
            cout << "Файл: ";
            cin.getline(fname, 256);
            ofstream(fname, ios::binary).write(key_buf, 16);
            cout << "Сохранен\n";
        }
        return 1;
    }
    
    cout << "Ключ: ";
    cin.getline(key_buf, buf_size);
    return 1;
}

// = ВИЖЕНЕР =

void vigenere_text(int encrypt) {
    char text[8192];
    char key[1024];
    unsigned char out[8192];
    
    if (encrypt != 0) cout << "Текст: ";
    else cout << "HEX строка: ";
    cin.getline(text, 8192);
    
    if (get_key_vigenere(key, 1024, 0) == 0) {
        error_msg(CRYPT_ERR_KEY);
        return;
    }
    
    ConstBuffer kb = {(unsigned char*)key, 0};
    size_t key_len = 0;
    while (key[key_len] != '\0') key_len = key_len + 1;
    kb.size = key_len;
    
    MutBuffer ob = {out, 8192};
    int res;
    
    if (encrypt != 0) {
        ConstBuffer ib = {(unsigned char*)text, 0};
        size_t text_len = 0;
        while (text[text_len] != '\0') text_len = text_len + 1;
        ib.size = text_len;
        res = vigenere_encrypt(kb, ib, &ob);
    } else {
        unsigned char bytes[8192];
        size_t bytes_len = hex_to_bytes(text, bytes, 8192);
        ConstBuffer ib = {bytes, bytes_len};
        res = vigenere_decrypt(kb, ib, &ob);
    }
    
    if (res != 0) { error_msg(res); return; }
    cout << "\nРезультат:\n";
    if (encrypt != 0) print_hex(ob.data, ob.size);
    else cout << (char*)ob.data << endl;
}

void vigenere_file(int encrypt) {
    char in[256];
    char out[256];
    char key[1024];
    vector<unsigned char> data;
    
    cout << "Входной файл: ";
    cin.getline(in, 256);
    cout << "Выходной файл: ";
    cin.getline(out, 256);
    
    if (create_dir(out) == 0) { error_msg(CRYPT_ERR_OUTPUT); return; }
    if (read_file(in, data) == 0) { error_msg(CRYPT_ERR_FILE); return; }
    
    cout << "Прочитано " << data.size() << " байт\n";
    if (get_key_vigenere(key, 1024, 0) == 0) { error_msg(CRYPT_ERR_KEY); return; }
    
    vector<unsigned char> out_data(data.size() + 1024);
    
    ConstBuffer kb = {(unsigned char*)key, 0};
    size_t key_len = 0;
    while (key[key_len] != '\0') key_len = key_len + 1;
    kb.size = key_len;
    
    ConstBuffer ib = {data.data(), data.size()};
    MutBuffer ob = {out_data.data(), out_data.size()};
    
    int res;
    if (encrypt != 0) res = vigenere_encrypt(kb, ib, &ob);
    else res = vigenere_decrypt(kb, ib, &ob);
    
    if (res != 0) { error_msg(res); return; }
    
    if (write_file(out, ob.data, ob.size) == 0) error_msg(CRYPT_ERR_FILE);
    else cout << "Сохранено " << ob.size << " байт\n";
}

// = ПЛЕЙФЕР =

void playfair_text(int encrypt) {
    char text[8192];
    char key[1024];
    unsigned char out[8192];
    
    if (encrypt != 0) {
        cout << "Текст (любые символы): ";
        cin.getline(text, 8192);
    } else {
        cout << "HEX строка: ";
        cin.getline(text, 8192);
    }
    
    cout << "Ключ: ";
    cin.getline(key, 1024);
    
    if (key[0] == '\0') {
        error_msg(CRYPT_ERR_KEY);
        return;
    }
    
    ConstBuffer kb = {(unsigned char*)key, 0};
    size_t key_len = 0;
    while (key[key_len] != '\0') key_len = key_len + 1;
    kb.size = key_len;
    
    MutBuffer ob = {out, 8192};
    int res;
    
    if (encrypt != 0) {
        ConstBuffer ib = {(unsigned char*)text, 0};
        size_t text_len = 0;
        while (text[text_len] != '\0') text_len = text_len + 1;
        ib.size = text_len;
        res = playfair_encrypt(kb, ib, &ob);
        
        if (res != 0) { error_msg(res); return; }
        
        cout << "\nРезультат (HEX): ";
        print_hex(ob.data, ob.size);
        
        cout << "Результат (текст): ";
        size_t i;
        for (i = 0; i < ob.size; i++) {
            if (is_printable(ob.data[i])) {
                cout << (char)ob.data[i];
            } else {
                cout << '[';
                printf("%02X", ob.data[i]);
                cout << ']';
            }
        }
        cout << endl;
        
    } else {
        unsigned char bytes[8192];
        size_t bytes_len = hex_to_bytes(text, bytes, 8192);
        ConstBuffer ib = {bytes, bytes_len};
        res = playfair_decrypt(kb, ib, &ob);
        
        if (res != 0) { error_msg(res); return; }
        
        cout << "\nРезультат (текст): ";
        size_t i;
        for (i = 0; i < ob.size; i++) {
            if (is_printable(ob.data[i])) {
                cout << (char)ob.data[i];
            } else {
                cout << '[';
                printf("%02X", ob.data[i]);
                cout << ']';
            }
        }
        cout << endl;
    }
}

void playfair_file(int encrypt) {
    char in[256];
    char out[256];
    char key[1024];
    vector<unsigned char> data;
    
    cout << "Входной файл: ";
    cin.getline(in, 256);
    cout << "Выходной файл: ";
    cin.getline(out, 256);
    
    if (create_dir(out) == 0) { error_msg(CRYPT_ERR_OUTPUT); return; }
    if (read_file(in, data) == 0) { error_msg(CRYPT_ERR_FILE); return; }
    
    cout << "Прочитано " << data.size() << " байт\n";
    cout << "Ключ: ";
    cin.getline(key, 1024);
    
    if (key[0] == '\0') {
        error_msg(CRYPT_ERR_KEY);
        return;
    }
    
    ConstBuffer kb = {(unsigned char*)key, 0};
    size_t key_len = 0;
    while (key[key_len] != '\0') key_len = key_len + 1;
    kb.size = key_len;
    
    vector<unsigned char> out_data(data.size() * 2 + 1024);
    ConstBuffer ib = {data.data(), data.size()};
    MutBuffer ob = {out_data.data(), out_data.size()};
    
    int res;
    if (encrypt != 0) {
        res = playfair_encrypt(kb, ib, &ob);
        if (res != 0) { error_msg(res); return; }
        
        if (write_file(out, ob.data, ob.size) == 0) error_msg(CRYPT_ERR_FILE);
        else {
            cout << "Сохранено " << ob.size << " байт\n";
            cout << "HEX (первые 64 байт): ";
            size_t show_size = ob.size;
            if (show_size > 64) show_size = 64;
            print_hex(ob.data, show_size);
            if (ob.size > 64) cout << "...\n";
        }
    } else {
        res = playfair_decrypt(kb, ib, &ob);
        if (res != 0) { error_msg(res); return; }
        
        if (write_file(out, ob.data, ob.size) == 0) error_msg(CRYPT_ERR_FILE);
        else {
            cout << "Сохранено " << ob.size << " байт\n";
        }
    }
}

// = ВЕРНАМ (XOR)=

void vernam_text(int encrypt) {
    char text[8192];
    char key[1024];
    unsigned char out[8192];
    
    if (encrypt != 0) {
        cout << "Текст: ";
        cin.getline(text, 8192);
    } else {
        cout << "HEX строка: ";
        cin.getline(text, 8192);
    }
    
    if (get_key_vernam(key, 1024) == 0) {
        error_msg(CRYPT_ERR_KEY);
        return;
    }
    
    ConstBuffer kb = {(unsigned char*)key, 0};
    size_t key_len = 0;
    while (key[key_len] != '\0') key_len = key_len + 1;
    kb.size = key_len;
    
    MutBuffer ob = {out, 8192};
    int res;
    
    if (encrypt != 0) {
        ConstBuffer ib = {(unsigned char*)text, 0};
        size_t text_len = 0;
        while (text[text_len] != '\0') text_len = text_len + 1;
        ib.size = text_len;
        res = vernam_encrypt(kb, ib, &ob);
        
        if (res != 0) { error_msg(res); return; }
        
        cout << "\nРезультат (HEX): ";
        // Выводим размер (input.size)
        print_hex(ob.data, ib.size);
        
    } else {
        unsigned char bytes[8192];
        size_t bytes_len = hex_to_bytes(text, bytes, 8192);
        ConstBuffer ib = {bytes, bytes_len};
        res = vernam_decrypt(kb, ib, &ob);
        
        if (res != 0) { error_msg(res); return; }
        
        cout << "\nРезультат: ";
        size_t i;
        for (i = 0; i < ob.size; i++) {
            if (is_printable(ob.data[i])) {
                cout << (char)ob.data[i];
            } else {
                cout << '[';
                printf("%02X", ob.data[i]);
                cout << ']';
            }
        }
        cout << endl;
    }
}

void vernam_file(int encrypt) {
    char in[256];
    char out[256];
    char key[1024];
    vector<unsigned char> data;
    
    cout << "Входной файл: ";
    cin.getline(in, 256);
    cout << "Выходной файл: ";
    cin.getline(out, 256);
    
    if (create_dir(out) == 0) { error_msg(CRYPT_ERR_OUTPUT); return; }
    if (read_file(in, data) == 0) { error_msg(CRYPT_ERR_FILE); return; }
    
    cout << "Прочитано " << data.size() << " байт\n";
    if (get_key_vernam(key, 1024) == 0) { error_msg(CRYPT_ERR_KEY); return; }
    
    vector<unsigned char> out_data(data.size());
    
    ConstBuffer kb = {(unsigned char*)key, 0};
    size_t key_len = 0;
    while (key[key_len] != '\0') key_len = key_len + 1;
    kb.size = key_len;
    
    ConstBuffer ib = {data.data(), data.size()};
    MutBuffer ob = {out_data.data(), out_data.size()};
    
    int res;
    if (encrypt != 0) {
        res = vernam_encrypt(kb, ib, &ob);
        if (res != 0) { error_msg(res); return; }
        
        if (write_file(out, ob.data, ob.size) == 0) error_msg(CRYPT_ERR_FILE);
        else {
            cout << "Сохранено " << ob.size << " байт\n";
        }
    } else {
        res = vernam_decrypt(kb, ib, &ob);
        if (res != 0) { error_msg(res); return; }
        
        if (write_file(out, ob.data, ob.size) == 0) error_msg(CRYPT_ERR_FILE);
        else {
            cout << "Сохранено " << ob.size << " байт\n";
        }
    }
}

// = RSA =

void generate_rsa_keys_direct(unsigned int* n, unsigned int* e, unsigned int* d) {
    *n = 3233;
    *e = 17;
    *d = 2753;
}

void rsa_key_generator() {
    cout << "\n=== ГЕНЕРАЦИЯ КЛЮЧЕЙ RSA ===\n";
    unsigned int n = 0, e = 0, d = 0;
    
    generate_rsa_keys_direct(&n, &e, &d);
    
    cout << "n = " << n << "\n";
    cout << "e = " << e << "\n";
    cout << "d = " << d << "\n";
    
    unsigned char pub_buf[8];
    unsigned char priv_buf[8];
    
    pub_buf[0] = (n >> 24) & 255;
    pub_buf[1] = (n >> 16) & 255;
    pub_buf[2] = (n >> 8) & 255;
    pub_buf[3] = n & 255;
    pub_buf[4] = (e >> 24) & 255;
    pub_buf[5] = (e >> 16) & 255;
    pub_buf[6] = (e >> 8) & 255;
    pub_buf[7] = e & 255;
    
    priv_buf[0] = (n >> 24) & 255;
    priv_buf[1] = (n >> 16) & 255;
    priv_buf[2] = (n >> 8) & 255;
    priv_buf[3] = n & 255;
    priv_buf[4] = (d >> 24) & 255;
    priv_buf[5] = (d >> 16) & 255;
    priv_buf[6] = (d >> 8) & 255;
    priv_buf[7] = d & 255;
    
    ofstream pub_out("public.key", ios::binary);
    if (pub_out.is_open()) {
        pub_out.write((const char*)pub_buf, 8);
        pub_out.close();
        cout << "Публичный ключ сохранен в public.key\n";
    }
    
    ofstream priv_out("private.key", ios::binary);
    if (priv_out.is_open()) {
        priv_out.write((const char*)priv_buf, 8);
        priv_out.close();
        cout << "Приватный ключ сохранен в private.key\n";
    }
    
    cout << "\nHEX для ручного ввода:\n";
    printf("Публичный ключ (HEX): %02X%02X%02X%02X%02X%02X%02X%02X\n",
           pub_buf[0], pub_buf[1], pub_buf[2], pub_buf[3],
           pub_buf[4], pub_buf[5], pub_buf[6], pub_buf[7]);
    
    printf("Приватный ключ (HEX): %02X%02X%02X%02X%02X%02X%02X%02X\n",
           priv_buf[0], priv_buf[1], priv_buf[2], priv_buf[3],
           priv_buf[4], priv_buf[5], priv_buf[6], priv_buf[7]);
    
    cout << "\nДля шифрования используйте public.key или HEX: 00000CA100000011\n";
    cout << "Для дешифрования используйте private.key или HEX: 00000CA100000AC1\n";
}

int get_rsa_key(unsigned char* key_buf, int is_public) {
    char choice[16];
    cout << "\n1) Загрузить из файла\n2) Ввести HEX с клавиатуры\nВыбор: ";
    cin.getline(choice, 16);
    
    if (str_equal(choice, "1")) {
        char fname[256];
        if (is_public != 0) {
            cout << "Имя файла (public.key): ";
        } else {
            cout << "Имя файла (private.key): ";
        }
        cin.getline(fname, 256);
        ifstream file(fname, ios::binary);
        if (!file.is_open()) {
            cout << "Ошибка: файл не найден\n";
            return 0;
        }
        file.read((char*)key_buf, 8);
        if (file.gcount() != 8) {
            cout << "Ошибка: файл должен содержать 8 байт\n";
            return 0;
        }
        cout << "Ключ загружен из файла " << fname << "\n";
        return 1;
    } else {
        char hex_key[32];
        cout << "Введите HEX строку (16 символов):\n";
        if (is_public != 0) {
            cout << "Публичный ключ: 00000CA100000011\n";
        } else {
            cout << "Приватный ключ: 00000CA100000AC1\n";
        }
        cout << "HEX: ";
        cin.getline(hex_key, 32);
        
        char clean[32];
        size_t clean_len = 0;
        for (size_t i = 0; hex_key[i] != '\0'; i++) {
            if (hex_key[i] != ' ' && hex_key[i] != '\t') {
                clean[clean_len] = hex_key[i];
                clean_len++;
            }
        }
        clean[clean_len] = '\0';
        
        if (clean_len != 16) {
            cout << "Ошибка: нужно 16 HEX символов (8 байт)\n";
            return 0;
        }
        
        size_t len = hex_to_bytes(clean, key_buf, 8);
        if (len != 8) {
            cout << "Ошибка: неверный HEX формат\n";
            return 0;
        }
        cout << "Ключ введен с клавиатуры\n";
        return 1;
    }
}

void rsa_process(int encrypt) {
    char text[8192];
    unsigned char out[8192];
    unsigned char key_buf[8];
    
    if (encrypt != 0) {
        cout << "Текст: ";
        cin.getline(text, 8192);
        cout << "\nВведите публичный ключ:\n";
        if (get_rsa_key(key_buf, 1) == 0) {
            error_msg(CRYPT_ERR_KEY);
            return;
        }
        
        ConstBuffer kb = {key_buf, 8};
        ConstBuffer ib = {(unsigned char*)text, 0};
        size_t text_len = 0;
        while (text[text_len] != '\0') text_len = text_len + 1;
        ib.size = text_len;
        MutBuffer ob = {out, 8192};
        
        int res = rsa_encrypt(kb, ib, &ob);
        if (res != 0) { error_msg(res); return; }
        
        cout << "\nРезультат (HEX): ";
        print_hex(ob.data, ob.size);
    } else {
        cout << "HEX строка: ";
        cin.getline(text, 8192);
        cout << "\nВведите приватный ключ:\n";
        if (get_rsa_key(key_buf, 0) == 0) {
            error_msg(CRYPT_ERR_KEY);
            return;
        }
        
        unsigned char input_bytes[8192];
        size_t input_len = hex_to_bytes(text, input_bytes, 8192);
        
        ConstBuffer kb = {key_buf, 8};
        ConstBuffer ib = {input_bytes, input_len};
        MutBuffer ob = {out, 8192};
        
        int res = rsa_decrypt(kb, ib, &ob);
        if (res != 0) { error_msg(res); return; }
        
        cout << "\nРезультат: ";
        size_t i;
        for (i = 0; i < ob.size; i++) {
            if (is_printable(ob.data[i])) {
                cout << (char)ob.data[i];
            } else {
                cout << '[';
                printf("%02X", ob.data[i]);
                cout << ']';
            }
        }
        cout << endl;
    }
}

// = ГЕНЕРАТОР СЛУЧАЙНОГО КЛЮЧА =

void key_generator() {
    char len_str[16];
    char key[256];
    cout << "Длина ключа: ";
    cin.getline(len_str, 16);
    
    size_t len = 16;
    if (len_str[0] != '\0') {
        len = 0;
        size_t i = 0;
        while (len_str[i] >= '0' && len_str[i] <= '9') {
            len = len * 10 + (len_str[i] - '0');
            i = i + 1;
        }
    }
    
    generate_key(key, len);
    key[len] = '\0';
    
    cout << "\nКлюч: " << key << "\nHEX: ";
    print_hex((unsigned char*)key, len);
    cout << "\nСохранить в файл? (y/n): ";
    char save[16];
    cin.getline(save, 16);
    if (str_equal(save, "y") || str_equal(save, "Y")) {
        char fname[256];
        cout << "Файл: ";
        cin.getline(fname, 256);
        ofstream(fname, ios::binary).write(key, len);
        cout << "Сохранен\n";
    }
}

// = ГЛАВНАЯ ФУНКЦИЯ =

int main() {
    char choice_str[16];
    
    if (login() == 0) {
        cout << "\nПрограмма завершена.\n";
        cout << "Нажмите Enter для выхода...";
        cin.get();
        return 1;
    }
    
    while (1) {
        cout << "\n========================================\n";
        cout << "           ГЛАВНОЕ МЕНЮ               \n";
        cout << "========================================\n";
        cout << "1)  Виженер (текст)\n";
        cout << "2)  Виженер (файл)\n";
        cout << "3)  Плейфер (текст)\n";
        cout << "4)  Плейфер (файл)\n";
        cout << "5)  Вернам (текст)\n";
        cout << "6)  Вернам (файл)\n";
        cout << "7)  RSA (шифрование)\n";
        cout << "8)  RSA (дешифрование)\n";
        cout << "9)  Генератор ключей RSA\n";
        cout << "10) Генератор случайного ключа\n";
        cout << "0)  Выход\n";
        cout << "========================================\n";
        cout << "Выбор: ";
        
        cin.getline(choice_str, 16);
        
        if (str_equal(choice_str, "0")) {
            cout << "\nДо свидания!\n";
            break;
        }
        
        if (str_equal(choice_str, "9")) {
            rsa_key_generator();
            continue;
        }
        
        if (str_equal(choice_str, "10")) {
            key_generator();
            continue;
        }
        
        if (str_equal(choice_str, "1")) {
            cout << "\n--- ВИЖЕНЕР (ТЕКСТ) ---\n";
            cout << "1) Шифрование\n2) Дешифрование\nВыбор: ";
            char mode[16];
            cin.getline(mode, 16);
            if (str_equal(mode, "1")) vigenere_text(1);
            else if (str_equal(mode, "2")) vigenere_text(0);
            else cout << "Неверный выбор\n";
        }
        else if (str_equal(choice_str, "2")) {
            cout << "\n--- ВИЖЕНЕР (ФАЙЛ) ---\n";
            cout << "1) Шифрование\n2) Дешифрование\nВыбор: ";
            char mode[16];
            cin.getline(mode, 16);
            if (str_equal(mode, "1")) vigenere_file(1);
            else if (str_equal(mode, "2")) vigenere_file(0);
            else cout << "Неверный выбор\n";
        }
        else if (str_equal(choice_str, "3")) {
            cout << "\n--- ПЛЕЙФЕР (ТЕКСТ) ---\n";
            cout << "1) Шифрование\n2) Дешифрование\nВыбор: ";
            char mode[16];
            cin.getline(mode, 16);
            if (str_equal(mode, "1")) playfair_text(1);
            else if (str_equal(mode, "2")) playfair_text(0);
            else cout << "Неверный выбор\n";
        }
        else if (str_equal(choice_str, "4")) {
            cout << "\n--- ПЛЕЙФЕР (ФАЙЛ) ---\n";
            cout << "1) Шифрование\n2) Дешифрование\nВыбор: ";
            char mode[16];
            cin.getline(mode, 16);
            if (str_equal(mode, "1")) playfair_file(1);
            else if (str_equal(mode, "2")) playfair_file(0);
            else cout << "Неверный выбор\n";
        }
        else if (str_equal(choice_str, "5")) {
            cout << "\n--- ВЕРНАМ (ТЕКСТ) ---\n";
            cout << "1) Шифрование\n2) Дешифрование\nВыбор: ";
            char mode[16];
            cin.getline(mode, 16);
            if (str_equal(mode, "1")) vernam_text(1);
            else if (str_equal(mode, "2")) vernam_text(0);
            else cout << "Неверный выбор\n";
        }
        else if (str_equal(choice_str, "6")) {
            cout << "\n--- ВЕРНАМ (ФАЙЛ) ---\n";
            cout << "1) Шифрование\n2) Дешифрование\nВыбор: ";
            char mode[16];
            cin.getline(mode, 16);
            if (str_equal(mode, "1")) vernam_file(1);
            else if (str_equal(mode, "2")) vernam_file(0);
            else cout << "Неверный выбор\n";
        }
        else if (str_equal(choice_str, "7")) {
            cout << "\n--- RSA (ШИФРОВАНИЕ) ---\n";
            rsa_process(1);
        }
        else if (str_equal(choice_str, "8")) {
            cout << "\n--- RSA (ДЕШИФРОВАНИЕ) ---\n";
            rsa_process(0);
        }
        else {
            cout << "Неверный выбор\n";
        }
    }
    
    return 0;
}
