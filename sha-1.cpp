#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

// Функции SHA-1
uint32_t ROTLEFT(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t S(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

uint32_t SHA1(std::string message) {
    const uint32_t k[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

    // Предобработка сообщения
    uint64_t ml = message.length() * 8;  // Длина сообщения в битах

    message += (char)0x80;  // Добавляем бит "1"

    while ((message.length() % 64) != 56) {
        message += (char)0x00;  // Добавляем байты "0"
    }

    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << ml;
    std::string ml_str = ss.str();

    for (int i = 14; i >= 0; i -= 2) {
        std::string byte = ml_str.substr(i, 2);
        unsigned int val;
        std::stringstream(byte) >> std::hex >> val;
        message += (char)val;
    }

    // Инициализация переменных
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Обработка сообщения
    for (size_t i = 0; i < message.length(); i += 64) {
        uint32_t w[80];
        for (size_t j = 0; j < 16; j++) {
            w[j] = (message[i + j * 4] << 24) | (message[i + j * 4 + 1] << 16) | (message[i + j * 4 + 2] << 8) | (message[i + j * 4 + 3]);
        }
        for (size_t j = 16; j < 80; j++) {
            w[j] = ROTLEFT((w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]), 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (size_t j = 0; j < 80; j++) {
            uint32_t f, k;
            if (j < 20) {
                f = Ch(b, c, d);
                k = 0x5A827999;
            }
            else if (j < 40) {
                f = (b ^ c ^ d);
                k = 0x6ED9EBA1;
            }
            else if (j < 60) {
                f = Maj(b, c, d);
                k = 0x8F1BBCDC;
            }
            else {
                f = (b ^ c ^ d);
                k = 0xCA62C1D6;
            }

            uint32_t temp = (ROTLEFT(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF;
            e = d;
            d = c;
            c = ROTLEFT(b, 30);
            b = a;
            a = temp;
        }
        h0 = (h0 + a) & 0xFFFFFFFF;
        h1 = (h1 + b) & 0xFFFFFFFF;
        h2 = (h2 + c) & 0xFFFFFFFF;
        h3 = (h3 + d) & 0xFFFFFFFF;
        h4 = (h4 + e) & 0xFFFFFFFF;
    }

    // Собираем результат
    return ((uint64_t)h0 << 32 | h1);
}

int main() {
    std::string input = "Hello, World!";
    uint32_t hash = SHA1(input);
    std::cout << "SHA-1 hash \"" << input << "\" : " << std::hex << std::setw(8) << std::setfill('0') << hash << std::endl;
    return 0;
}
