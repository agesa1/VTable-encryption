#include <iostream>
#include <iomanip>
#include "vtableenc.h"

class GameEntity {
public:
    virtual void update() {
        std::cout << "GameEntity::update()" << std::endl;
    }

    virtual int getHealth() {
        return 100;
    }

    virtual void takeDamage(int amount) {
        std::cout << "GameEntity::takeDamage(" << amount << ")" << std::endl;
    }

    virtual ~GameEntity() {}
};

class Player : public GameEntity {
private:
    int health;
    int score;

public:
    Player() : health(100), score(0) {}

    void update() override {
        std::cout << "Player::update() - health=" << health << " score=" << score << std::endl;
    }

    int getHealth() override {
        return health;
    }

    void takeDamage(int amount) override {
        health -= amount;
        std::cout << "Player::takeDamage(" << amount << ") - remaining=" << health << std::endl;
    }

    void addScore(int points) {
        score += points;
        std::cout << "Player::addScore(" << points << ") - total=" << score << std::endl;
    }
};

void printVTablePointer(void* obj, const char* label) {
    void** vtablePtr = *static_cast<void***>(obj);
    std::cout << label << std::hex << std::setw(16) << std::setfill('0')
        << reinterpret_cast<uintptr_t>(vtablePtr) << std::dec << std::endl;
}

void printVTableBytes(void* obj, const char* label) {
    std::cout << label;
    uint8_t* bytes = static_cast<uint8_t*>(obj);
    for (size_t i = 0; i < sizeof(void*); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(bytes[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== VTable Encryption ===" << std::endl;

    Player player;

    std::cout << "\nOriginal state:" << std::endl;
    printVTablePointer(&player, "vtable pointer: 0x");
    printVTableBytes(&player, "vtable bytes: ");
    player.update();
    player.takeDamage(25);

    VTableEncryption enc;

    std::cout << "\nEncrypting vtable..." << std::endl;
    enc.encryptObject(&player);
    printVTablePointer(&player, "encrypted vtable: 0x");
    printVTableBytes(&player, "encrypted bytes: ");

    std::cout << "\nDecrypting vtable..." << std::endl;
    enc.decryptObject(&player);
    printVTablePointer(&player, "decrypted vtable: 0x");
    printVTableBytes(&player, "decrypted bytes: ");
    player.update();
    std::cout << "health: " << player.getHealth() << std::endl;

    std::cout << "\n=== VTable Wrapper ===" << std::endl;

    Player* p = new Player();
    SecureVTable<Player> secure(p);

    std::cout << "\nCalling methods through wrapper:" << std::endl;
    secure.call(&Player::update);
    secure.call(&Player::takeDamage, 30);
    secure.call(&Player::addScore, 500);

    int hp = secure.call(&Player::getHealth);
    std::cout << "health returned: " << hp << std::endl;

    std::cout << "\nVTable remains encrypted between calls" << std::endl;
    printVTableBytes(p, "vtable bytes: ");

    delete p;

    std::cout << "\n=== Multiple Objects ===" << std::endl;

    Player p1, p2, p3;
    VTableEncryption enc1, enc2, enc3;

    std::cout << "Encrypting 3 objects with different keys:" << std::endl;
    enc1.encryptObject(&p1);
    enc2.encryptObject(&p2);
    enc3.encryptObject(&p3);

    printVTableBytes(&p1, "p1 encrypted: ");
    printVTableBytes(&p2, "p2 encrypted: ");
    printVTableBytes(&p3, "p3 encrypted: ");

    std::cout << "\nDecrypting and calling:" << std::endl;
    enc2.decryptObject(&p2);
    p2.update();
    enc2.encryptObject(&p2);

    enc1.decryptObject(&p1);
    p1.takeDamage(10);
    enc1.encryptObject(&p1);

    enc3.decryptObject(&p3);
    p3.addScore(999);
    enc3.encryptObject(&p3);

    return 0;
}
