#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <filesystem>
#include "buffer.h"
#include "error_codes.h"
using namespace std;
namespace fs = filesystem;
// Прототипы функций шифров
const char* vernam_get_name(void);
int vernam_encrypt(ConstBuffer, ConstBuffer, MutBuffer*);
int vernam_decrypt(ConstBuffer, ConstBuffer, MutBuffer*);
const char* rsa_get_name(void);
int rsa_encrypt(ConstBuffer, ConstBuffer, MutBuffer*);
int rsa_decrypt(ConstBuffer, ConstBuffer, MutBuffer*);
int rsa_generate_keys(unsigned int*, unsigned int*, unsigned int*);
//  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============
// Вывод данных в шестнадцатеричном формате
void print_hex(const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}
// Очистка буфера ввода
void clear_input() {
    cin.clear();
    cin.ignore(10000, '\n');
}
// Вывод сообщения об ошибке по коду
void error_msg(int code) {
    cout << "\n[ОШИБКА] ";
    if (code == CRYPT_ERR_KEY) cout << "неверный ключ";
    else if (code == CRYPT_ERR_INPUT) cout << "ошибка ввода";
    else if (code == CRYPT_ERR_OUTPUT) cout << "ошибка вывода";
    else if (code == CRYPT_ERR_FILE) cout << "ошибка файла";
    else cout << "код " << code;
    cout << endl;
}
// Генерация случайного ключа заданной длины (символы 33-126)
string generate_key(size_t len) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(33, 126);
    string key;
    for (size_t i = 0; i < len; ++i) {
        key.push_back(static_cast<char>(dis(gen)));
    }
    return key;
}
// Преобразование HEX строки в массив байт
vector<unsigned char> hex_to_bytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i = i + 2) {
        char hx[3];
        hx[0] = hex[i];
        hx[1] = hex[i + 1];
        hx[2] = 0;
        long val = strtol(hx, 0, 16);
        bytes.push_back(static_cast<unsigned char>(val));
    }
    return bytes;
}
// Чтение файла в вектор байт
bool read_file(const string& path, vector<unsigned char>& data) {
    ifstream f(path, ios::binary);
    if (f.is_open() == 0) return false;
    data.assign(istreambuf_iterator<char>(f), istreambuf_iterator<char>());
    return true;
}
// Запись вектора байт в файл
bool write_file(const string& path, const unsigned char* data, size_t size) {
    ofstream f(path, ios::binary);
    if (f.is_open() == 0) return false;
    f.write((const char*)data, size);
    return true;
}
// Создание директории для выходного файла
bool create_dir(const string& path) {
    fs::path dir = fs::path(path).parent_path();
    if (dir.empty() == 0 && fs::exists(dir) == 0) {
        return fs::create_directories(dir);
    }
    return true;
}
// = РАБОТА С КЛЮЧАМИ ВЕРНАМ =
// Получение ключа для Вернама (ввод/файл/генерация)
string get_key_for_vernam() {
    cout << "\n1) Ввести вручную\n2) Загрузить из файла\n3) Сгенерировать\nВыбор: ";
    string c;
    getline(cin, c);
    
    if (c == "2") {
        string f;
        cout << "Файл: ";
        getline(cin, f);
        ifstream file(f, ios::binary);
        if (file.is_open() == 0) return "";
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        return content;
    }
    
    if (c == "3") {
        string k = generate_key(16);
        cout << "Ключ: " << k << "\nHEX: ";
        print_hex((const unsigned char*)k.c_str(), k.size());
        cout << "Сохранить в файл? (y/n): ";
        string s;
        getline(cin, s);
        if (s == "y" || s == "Y") {
            string f;
            cout << "Файл: ";
            getline(cin, f);
            ofstream out(f, ios::binary);
            if (out.is_open()) {
                out.write(k.c_str(), k.size());
                cout << "Сохранен\n";
            }
        }
        return k;
    }
    
    cout << "Ключ: ";
    string k;
    getline(cin, k);
    return k;
}
// = ОПЕРАЦИИ ВЕРНАМ =
// Шифрование/дешифрование текста Вернам
void vernam_text(int encrypt) {
    string text, key;
    unsigned char out[8192];
    
    if (encrypt) cout << "Текст: ";
    else cout << "HEX строка: ";
    getline(cin, text);
    
    key = get_key_for_vernam();
    if (key.empty()) {
        error_msg(CRYPT_ERR_KEY);
        return;
    }
    
    ConstBuffer kb = {(const unsigned char*)key.c_str(), key.size()};
    MutBuffer ob = {out, 8192};
    int res;
    
    if (encrypt) {
        ConstBuffer ib = {(const unsigned char*)text.c_str(), text.size()};
        res = vernam_encrypt(kb, ib, &ob);
    } else {
        vector<unsigned char> bytes = hex_to_bytes(text);
        ConstBuffer ib = {bytes.data
(), bytes.size()};
        res = vernam_decrypt(kb, ib, &ob);
    }
    
    if (res != CRYPT_OK) {
        error_msg(res);
        return;
    }
    
    cout << "\nРезультат:\n";
    if (encrypt) {
        print_hex(out, ob.size);
    } else {
        cout << string((char*)out, ob.size) << endl;
    }
}
// Шифрование/дешифрование файла Вернам
void vernam_file(int encrypt) {
    string in, out, key;
    vector<unsigned char> data;
    
    cout << "Входной файл: ";
    getline(cin, in);
    cout << "Выходной файл: ";
    getline(cin, out);
    
    if (create_dir(out) == 0) {
        error_msg(CRYPT_ERR_OUTPUT);
        return;
    }
    if (read_file(in, data) == 0) {
        error_msg(CRYPT_ERR_FILE);
        return;
    }
    
    cout << "Прочитано " << data.size() << " байт\n";
    key = get_key_for_vernam();
    if (key.empty()) {
        error_msg(CRYPT_ERR_KEY);
        return;
    }
    
    vector<unsigned char> out_data(data.size());
    ConstBuffer kb = {(const unsigned char*)key.c_str(), key.size()};
    ConstBuffer ib = {data.data
(), data.size()};
    MutBuffer ob = {out_data.data
(), out_data.size()};
    
    int res;
    if (encrypt) res = vernam_encrypt(kb, ib, &ob);
    else res = vernam_decrypt(kb, ib, &ob);
    
    if (res != CRYPT_OK) {
        error_msg(res);
        return;
    }
    
    if (write_file(out, ob.data
, ob.size) == 0) {
        error_msg(CRYPT_ERR_FILE);
    } else {
        cout << "Сохранено " << ob.size << " байт\n";
    }
}
// = ГЕНЕРАТОР КЛЮЧЕЙ RSA =
// Генерация и сохранение ключей RSA
void rsa_key_generator() {
    cout <<"\n= ГЕНЕРАЦИЯ КЛЮЧЕЙ RSA =\n";
    unsigned int n = 0;
    unsigned int e = 0;
    unsigned int d = 0;
    
    int res = rsa_generate_keys(&n, &e, &d);
    if (res != CRYPT_OK) {
        error_msg(res);
        return;
    }
    
    cout << "\nПубличный ключ (n, e):\n";
    cout << "n = " << n << "\n";
    cout << "e = " << e << "\n";
    cout << "\nПриватный ключ (n, d):\n";
    cout << "n = " << n << "\n";
    cout << "d = " << d << "\n";
    
    cout << "\nСохранить ключи в файлы? (y/n): ";
    string s;
    getline(cin, s);
    if (s == "y" || s == "Y") {
        string pub_file, priv_file;
        cout << "Файл для публичного ключа: ";
        getline(cin, pub_file);
        cout << "Файл для приватного ключа: ";
        getline(cin, priv_file);
        
        // Сохранение публичного ключа (n, e)
        ofstream pub_out(pub_file, ios::binary);
        if (pub_out.is_open()) {
            for (int shift = 24; shift >= 0; shift = shift - 8) {
                unsigned char byte = (n >> shift) & 255;
                pub_out.put(byte);
            }
            for (int shift = 24; shift >= 0; shift = shift - 8) {
                unsigned char byte = (e >> shift) & 255;
                pub_out.put(byte);
            }
            pub_out.close();
            cout << "Публичный ключ сохранен\n";
        }
        
        // Сохранение приватного ключа (n, d)
        ofstream priv_out(priv_file, ios::binary);
        if (priv_out.is_open()) {
            for (int shift = 24; shift >= 0; shift = shift - 8) {
                unsigned char byte = (n >> shift) & 255;
                priv_out.put(byte);
            }
            for (int shift = 24; shift >= 0; shift = shift - 8) {
                unsigned char byte = (d >> shift) & 255;
                priv_out.put(byte);
            }
            priv_out.close();
            cout << "Приватный ключ сохранен\n";
        }
    }
}
// = ПОЛУЧЕНИЕ КЛЮЧА RSA =
// Получение ключа RSA (из файла или HEX)
string get_rsa_key(int is_public) {
    cout << "\n1) Из файла\n2) Ввести HEX\nВыбор: ";
    string c;
    getline(cin, c);
    
    if (c == "1") {
        string f;
        cout << "Файл: ";
        getline(cin, f);
        ifstream file(f, ios::binary);
        if (file.is_open() == 0) return "";
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        return content;
    } else {
        string hex_key;
        if (is_public) {
            cout << "HEX ключ (8 байт: n=4 байт, e=4 байт): ";
        } else {
            cout << "HEX ключ (8 байт: n=4 байт, d=4 байт): ";
        }
        getline(cin, hex_key);
        vector<unsigned char> bytes = hex_to_bytes(hex_key);
        string content(bytes.begin(), bytes.end());
        return content;
    }
}
// = ОПЕРАЦИИ RSA =
// Шифрование/дешифрование RSA
void rsa_process(int encrypt) {
    string text;
    unsigned char out[8192];
    
    if (encrypt) {
        cout << "Текст: ";
        getline(cin, text);
        
        cout << "Введите публичный ключ:\n";
        string key_data = get_rsa_key(1);
        if (key_data.size() < 8) {
            error_msg(CRYPT_ERR_KEY);
            return;
        }
        
        ConstBuffer kb = {(const unsigned char*)key_data.c_str(), key_data.size()};
        ConstBuffer ib = {(const unsigned char*)text.c_str(), text.size()};
        MutBuffer ob = {out, 8192};
        
        int res = rsa_encrypt(kb, ib, &ob);
        if (res != CRYPT_OK) {
            error_msg(res);
            return;
        }
        
        cout << "\nРезультат (HEX): ";
        print_hex(out, ob.size);
    } else {
        cout << "HEX строка: ";
        getline(cin, text);
        
        cout << "Введите приватный ключ:\n";
        string key_data = get_rsa_key(0);
        if (key_data.size() < 8) {
            error_msg(CRYPT_ERR_KEY);
            return;
        }
        
        vector<unsigned char> input_bytes = hex_to_bytes(text);
        ConstBuffer kb = {(const unsigned char*)key_data.c_str(), key_data.size()};
        ConstBuffer ib = {input_bytes.data
(), input_bytes.size()};
        MutBuffer ob = {out, 8192};
        
        int res = rsa_decrypt(kb, ib, &ob);
        if (res != CRYPT_OK) {
            error_msg(res);
            return;
        }
        
        cout << "\nРезультат: " << string((char*)out, ob.size) << endl;
    }
}
// = ГЛАВНАЯ ФУНКЦИЯ =
int main() {
    cout << "=== КРИПТОГРАФИЧЕСКИЙ КАЛЬКУЛЯТОР ===\n";
    cout << "Вернам (XOR): любые символы, вывод в HEX\n";
    cout << "RSA: шифрование до 255 байт\n";
    
    while (1) {
        cout << "\n1) Вернам (текст)\n2) Вернам (файл)\n";
        cout << "3) RSA (шифрование)\n4) RSA (дешифрование)\n";
        cout << "5) Генератор ключей RSA\n6) Выход\nВыбор: ";
        
        int c = 0;
        cin >> c;
        clear_input();
        
        if (c == 6) {
            cout << "До свидания!\n";
            break;
        }
        if (c == 5) {
            rsa_key_generator();
            continue;
        }
        if (c == 1) {
            vernam_text(1);
        } else if (c == 2) {
            vernam_file(1);
        } else if (c == 3) {
            rsa_process(1);
        } else if (c == 4) {
            rsa_process(0);
        } else {
            cout << "Неверный выбор\n";
        }
    }
    return 0;
}
