#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <filesystem>
#include <cctype>
#include "buffer.h"
#include "error_codes.h"

using namespace std;
namespace fs = filesystem;

const char* vigenere_get_name(void);
int vigenere_encrypt(ConstBuffer, ConstBuffer, MutBuffer*);
int vigenere_decrypt(ConstBuffer, ConstBuffer, MutBuffer*);
const char* playfair_get_name(void);
int playfair_encrypt(ConstBuffer, ConstBuffer, MutBuffer*);
int playfair_decrypt(ConstBuffer, ConstBuffer, MutBuffer*);

void print_hex(const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++) printf("%02X", data[i]);
    printf("\n");
}

void clear_input() { cin.clear(); cin.ignore(10000, '\n'); }

void error_msg(int code) {
    cout << "\n[ОШИБКА] ";
    switch(code) {
        case CRYPT_ERR_KEY: cout << "неверный ключ"; break;
        case CRYPT_ERR_INPUT: cout << "ошибка ввода"; break;
        case CRYPT_ERR_OUTPUT: cout << "ошибка вывода"; break;
        case CRYPT_ERR_FILE: cout << "ошибка файла"; break;
        default: cout << "код " << code;
    }
    cout << endl;
}

string generate_key(size_t len) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(33, 126);
    string key;
    for (size_t i = 0; i < len; i++) key += (char)dis(gen);
    return key;
}

vector<unsigned char> hex_to_bytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        if (isxdigit(hex[i]) && isxdigit(hex[i+1])) {
            char hx[3] = {hex[i], hex[i+1], 0};
            bytes.push_back((unsigned char)strtol(hx, NULL, 16));
        }
    }
    return bytes;
}

bool read_file(const string& path, vector<unsigned char>& data) {
    ifstream f(path, ios::binary);
    if (!f) return false;
    data.assign(istreambuf_iterator<char>(f), istreambuf_iterator<char>());
    return true;
}

bool write_file(const string& path, const unsigned char* data, size_t size) {
    ofstream f(path, ios::binary);
    if (!f) return false;
    f.write((char*)data, size);
    return true;
}

bool create_dir(const string& path) {
    fs::path dir = fs::path(path).parent_path();
    if (!dir.empty() && !fs::exists(dir)) return fs::create_directories(dir);
    return true;
}

string get_key(int hint) {
    cout << "\n1) Ввести вручную\n2) Загрузить из файла\n3) Сгенерировать\nВыбор: ";
    string c; getline(cin, c);
    
    if (c == "2") {
        string f; cout << "Файл: "; getline(cin, f);
        ifstream file(f, ios::binary);
        if (!file) return "";
        return string(istreambuf_iterator<char>(file), istreambuf_iterator<char>());
    }
    
    if (c == "3") {
        size_t len = hint ? hint : 16;
        string k = generate_key(len);
        cout << "Ключ: " << k << "\nHEX: "; print_hex((unsigned char*)k.c_str(), k.size());
        cout << "Сохранить в файл? (y/n): "; string s; getline(cin, s);
        if (s == "y") {
            string f; cout << "Файл: "; getline(cin, f);
            ofstream(f, ios::binary).write(k.c_str(), k.size());
            cout << "Сохранен\n";
        }
        return k;
    }
    
    cout << "Ключ: "; string k; getline(cin, k);
    return k;
}

void vigenere_text(int encrypt) {
    string text, key;
    unsigned char out[8192];
    
    if (encrypt) cout << "Текст: ";
    else cout << "HEX строка: ";
    getline(cin, text);
    
    key = get_key(0);
    if (key.empty()) { error_msg(CRYPT_ERR_KEY); return; }
    
    ConstBuffer kb = {(unsigned char*)key.c_str(), key.size()};
    MutBuffer ob = {out, sizeof(out)};
    int res;
    
    if (encrypt) {
        ConstBuffer ib = {(unsigned char*)text.c_str(), text.size()};
        res = vigenere_encrypt(kb, ib, &ob);
    } else {
        vector<unsigned char> bytes = hex_to_bytes(text);
        ConstBuffer ib = {bytes.data(), bytes.size()};
        res = vigenere_decrypt(kb, ib, &ob);
    }
    
    if (res) { error_msg(res); return; }
    cout << "\nРезультат:\n";
    if (encrypt) print_hex(out, ob.size);
    else cout << string((char*)out, ob.size) << endl;
}

void playfair_text(int encrypt) {
    string text, key;
    unsigned char out[8192];
    
    if (encrypt) cout << "Текст (латиница): ";
    else cout << "Шифротекст: ";
    getline(cin, text);
    
    cout << "Ключ: "; getline(cin, key);
    if (key.empty()) { error_msg(CRYPT_ERR_KEY); return; }
    
    ConstBuffer kb = {(unsigned char*)key.c_str(), key.size()};
    ConstBuffer ib = {(unsigned char*)text.c_str(), text.size()};
    MutBuffer ob = {out, sizeof(out)};
    int res = encrypt ? playfair_encrypt(kb, ib, &ob) : playfair_decrypt(kb, ib, &ob);
    
    if (res) { error_msg(res); return; }
    cout << "\nРезультат: " << string((char*)out, ob.size) << endl;
}

void vigenere_file(int encrypt) {
    string in, out, key;
    vector<unsigned char> data;
    
    cout << "Входной файл: "; getline(cin, in);
    cout << "Выходной файл: "; getline(cin, out);
    
    if (!create_dir(out)) { error_msg(CRYPT_ERR_OUTPUT); return; }
    if (!read_file(in, data)) { error_msg(CRYPT_ERR_FILE); return; }
    
    cout << "Прочитано " << data.size() << " байт\n";
    key = get_key(0);
    if (key.empty()) { error_msg(CRYPT_ERR_KEY); return; }
    
    vector<unsigned char> out_data(data.size() + 1024);
    ConstBuffer kb = {(unsigned char*)key.c_str(), key.size()};
    ConstBuffer ib = {data.data(), data.size()};
    MutBuffer ob = {out_data.data(), out_data.size()};
    
    int res = encrypt ? vigenere_encrypt(kb, ib, &ob) : vigenere_decrypt(kb, ib, &ob);
    if (res) { error_msg(res); return; }
    
    if (!write_file(out, out_data.data(), ob.size)) error_msg(CRYPT_ERR_FILE);
    else cout << "Сохранено " << ob.size << " байт\n";
}

void playfair_file(int encrypt) {
    string in, out, key;
    vector<unsigned char> data;
    
    cout << "Входной файл: "; getline(cin, in);
    cout << "Выходной файл: "; getline(cin, out);
    
    if (!create_dir(out)) { error_msg(CRYPT_ERR_OUTPUT); return; }
    if (!read_file(in, data)) { error_msg(CRYPT_ERR_FILE); return; }
    
    cout << "Прочитано " << data.size() << " байт\n";
    cout << "Ключ: "; getline(cin, key);
    if (key.empty()) { error_msg(CRYPT_ERR_KEY); return; }
    
    vector<unsigned char> out_data(data.size() * 2 + 1024);
    ConstBuffer kb = {(unsigned char*)key.c_str(), key.size()};
    ConstBuffer ib = {data.data(), data.size()};
    MutBuffer ob = {out_data.data(), out_data.size()};
    
    int res = encrypt ? playfair_encrypt(kb, ib, &ob) : playfair_decrypt(kb, ib, &ob);
    if (res) { error_msg(res); return; }
    
    if (!write_file(out, out_data.data(), ob.size)) error_msg(CRYPT_ERR_FILE);
    else cout << "Сохранено " << ob.size << " байт\n";
}

void key_generator() {
    cout << "Длина ключа: ";
    string l; getline(cin, l);
    size_t len = l.empty() ? 16 : stoi(l);
    string k = generate_key(len);
    cout << "\nКлюч: " << k << "\nHEX: ";
    print_hex((unsigned char*)k.c_str(), k.size());
    cout << "\nСохранить в файл? (y/n): ";
    string s; getline(cin, s);
    if (s == "y") {
        string f; cout << "Файл: "; getline(cin, f);
        ofstream(f, ios::binary).write(k.c_str(), k.size());
        cout << "Сохранен\n";
    }
}

int main() {
    cout << "=== КРИПТОГРАФИЧЕСКИЙ КАЛЬКУЛЯТОР ===\n";
    cout << "Виженер: любые символы, вывод в HEX\n";
    cout << "Плейфер: только латиница A-Z\n";
    
    while (true) {
        cout << "\n1) Виженер (текст)\n2) Плейфер (текст)\n";
        cout << "3) Виженер (файл)\n4) Плейфер (файл)\n";
        cout << "5) Генератор ключей\n6) Выход\nВыбор: ";
        
        int c, m; cin >> c; clear_input();
        if (c == 6) { cout << "До свидания!\n"; break; }
        if (c == 5) { key_generator(); continue; }
        if (c < 1 || c > 4) { cout << "Неверный выбор\n"; continue; }
        
        cout << "1) Шифрование\n2) Дешифрование\nВыбор: ";
        cin >> m; clear_input();
        if (m != 1 && m != 2) { cout << "Неверный выбор\n"; continue; }
        
        switch(c) {
            case 1: vigenere_text(m == 1); break;
            case 2: playfair_text(m == 1); break;
            case 3: vigenere_file(m == 1); break;
            case 4: playfair_file(m == 1); break;
        }
    }
    return 0;
}
