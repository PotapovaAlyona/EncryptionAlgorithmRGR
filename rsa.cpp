#include "rsa.h"
// Проверка числа на простоту
static int is_prime(unsigned int num) {
    if (num < 2) return 0;
    if (num == 2) return 1;
    if (num % 2 == 0) return 0;
    for (unsigned int i = 3; i * i <= num; i = i + 2) {
        if (num % i == 0) return 0;
    }
    return 1;
}
// Алгоритм Евклида для НОД
static unsigned int gcd(unsigned int a, unsigned int b) {
    while (b != 0) {
        unsigned int t = b;
        b = a % b;
        a = t;
    }
    return a;
}
// Быстрое возведение в степень по модулю
static unsigned int mod_pow(unsigned int base, unsigned int exp, unsigned int mod) {
    unsigned int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2;
    }
    return result;
}
// Расширенный алгоритм Евклида (обратное число по модулю)
static unsigned int mod_inverse(unsigned int a, unsigned int m) {
    int m0 = m;
    int y = 0;
    int x = 1;
    int a1 = a;
    
    if (m == 1) return 0;
    
    while (a1 > 1) {
        int q = a1 / m;
        int t = m;
        m = a1 % m;
        a1 = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    
    if (x < 0) x = x + m0;
    return x;
}
// Генерация простого числа из предопределённого списка
static unsigned int generate_prime() {
    unsigned int primes[] = {61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331};
    size_t index = 0;
    for (size_t i = 0; i < sizeof(primes)/sizeof(primes[0]); ++i) {
        if (primes[i] > 60) {
            index = i;
            break;
        }
    }
    return primes[index];
}
// Возвращает имя шифра
const char* rsa_get_name(void) {
    return "RSA Cipher";
}
// Размер ключа (0 = переменный)
size_t rsa_get_key_size(void) {
    return 0;
}
// Размер выходных данных (примерно в 4 раза больше входных)
size_t rsa_get_output_size(size_t input_size, int mode) {
    return input_size * 4;
}
// Генерация пары ключей RSA
int rsa_generate_keys(unsigned int* n, unsigned int* e, unsigned int* d) {
    unsigned int p = generate_prime();  // первое простое
    unsigned int q = generate_prime();  // второе простое
    
    while (p == q) {
        q = generate_prime();
    }
    
    unsigned int phi_n = (p - 1) * (q - 1);  // функция Эйлера
    
    unsigned int public_e = 65537;  // стандартная открытая экспонента
    
    // e должно быть взаимно просто с φ(n)
    while (gcd(public_e, phi_n) != 1) {
        public_e = public_e + 2;
    }
    
    unsigned int private_d = mod_inverse(public_e, phi_n);  // d = e^(-1) mod φ(n)
    
    *n = p * q;  // модуль
    *e = public_e;  // открытая экспонента
    *d = private_d;  // закрытая экспонента
    
    return CRYPT_OK;
}
