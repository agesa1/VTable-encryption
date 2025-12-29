#ifndef VTABLEENC_H
#define VTABLEENC_H

#include <cstdint>
#include <cstring>
#include <random>

class VTableEncryption {
private:
    uint64_t k1, k2, k3;
    std::mt19937_64 gen;

    inline uint64_t rotl(uint64_t x, int r) {
        return (x << r) | (x >> (64 - r));
    }

    inline uint64_t rotr(uint64_t x, int r) {
        return (x >> r) | (x << (64 - r));
    }

    inline uint8_t rotl8(uint8_t x, int r) {
        r = r & 7;
        return (x << r) | (x >> (8 - r));
    }

    inline uint8_t rotr8(uint8_t x, int r) {
        r = r & 7;
        return (x >> r) | (x << (8 - r));
    }

    uint64_t mix(uint64_t v, uint64_t s) {
        v ^= s;
        v *= 0x9e3779b97f4a7c15ULL;
        v = rotl(v, 31);
        v *= 0xbf58476d1ce4e5b9ULL;
        return v;
    }

    void expandKey(uint64_t seed, size_t len) {
        gen.seed(seed);
        k1 = gen();
        k2 = gen();
        k3 = gen();

        for (size_t i = 0; i < (len & 0xFF); i++) {
            k1 = mix(k1, k2);
            k2 = mix(k2, k3);
            k3 = mix(k3, k1);
        }
    }

    uint8_t getKeyByte(size_t idx) {
        uint64_t pos = idx;
        uint64_t h = k1;

        h ^= mix(pos, k2);
        h = rotl(h, 13);
        h ^= mix(pos * k3, k1);
        h = rotr(h, 7);
        h ^= k3;

        return static_cast<uint8_t>((h ^ (h >> 32)) & 0xFF);
    }

    void transform(uint8_t* data, size_t size, uint32_t salt, bool encrypt) {
        for (size_t i = 0; i < size; i++) {
            uint8_t kb = getKeyByte(i + salt);

            if (encrypt) {
                data[i] ^= kb;
                data[i] = rotl8(data[i], (kb & 7));
                data[i] ^= getKeyByte(size - i - 1 + salt);
            }
            else {
                data[i] ^= getKeyByte(size - i - 1 + salt);
                data[i] = rotr8(data[i], (kb & 7));
                data[i] ^= kb;
            }
        }
    }

    uint64_t seed;
    uint32_t salt;

public:
    VTableEncryption() {
        std::random_device rd;
        seed = (static_cast<uint64_t>(rd()) << 32) | rd();
        salt = rd();
        expandKey(seed, 256);
    }

    void encryptVTable(void* obj) {
        void*** vtablePtr = static_cast<void***>(obj);
        void** vtable = *vtablePtr;

        expandKey(seed, sizeof(void*) + salt);
        transform(reinterpret_cast<uint8_t*>(vtablePtr), sizeof(void*), salt, true);
    }

    void decryptVTable(void* obj) {
        expandKey(seed, sizeof(void*) + salt);
        transform(reinterpret_cast<uint8_t*>(obj), sizeof(void*), salt, false);
    }

    template<typename T>
    void encryptObject(T* obj) {
        encryptVTable(static_cast<void*>(obj));
    }

    template<typename T>
    void decryptObject(T* obj) {
        decryptVTable(static_cast<void*>(obj));
    }
};

template<typename Base>
class SecureVTable {
private:
    Base* obj;
    VTableEncryption enc;

public:
    SecureVTable(Base* ptr) : obj(ptr) {
        enc.encryptObject(obj);
    }

    ~SecureVTable() {
        enc.decryptObject(obj);
    }

    template<typename Ret, typename... Args>
    Ret call(Ret(Base::* f)(Args...), Args&&... args) {
        enc.decryptObject(obj);
        Ret result = (obj->*f)(std::forward<Args>(args)...);
        enc.encryptObject(obj);
        return result;
    }

    template<typename... Args>
    void call(void (Base::* f)(Args...), Args&&... args) {
        enc.decryptObject(obj);
        (obj->*f)(std::forward<Args>(args)...);
        enc.encryptObject(obj);
    }

    Base* get() {
        enc.decryptObject(obj);
        Base* temp = obj;
        enc.encryptObject(obj);
        return temp;
    }
};

#endif
