# VTable-encryption

## Overview

Encrypts the vtable pointer stored at the beginning of C++ objects with virtual functions. Prevents attackers from:
- Locating virtual function addresses
- Hooking virtual methods
- Analyzing class hierarchies
- Tampering with polymorphic behavior

## Features

- **Multi-Layer Encryption**: XOR + bit rotation + dynamic key derivation
- **Per-Object Keys**: Each instance can use different encryption
- **Automatic Wrapper**: SecureVTable template handles encrypt/decrypt
- **Zero Overhead**: Only encrypts 8 bytes (vtable pointer)
- **Header-Only**: Single file implementation

## How It Works
```
Object Memory Layout:
[VTable Pointer] [Member Data...]
     ↓ encrypt
[Encrypted Ptr] [Member Data...]
```

When encrypted, the vtable pointer becomes garbage. Virtual functions only work after decryption.

## Usage

### Manual Encryption
```cpp
#include "vtableenc.h"

class Player {
public:
    virtual void update() { }
    virtual int getHealth() { return 100; }
};

Player player;
VTableEncryption enc;

enc.encryptObject(&player);  // vtable pointer encrypted
// player.update();          // CRASH - vtable invalid

enc.decryptObject(&player);  // vtable pointer restored
player.update();             // works normally
```

### Automatic Wrapper
```cpp
Player* p = new Player();
SecureVTable secure(p);

// vtable automatically decrypted before call, re-encrypted after
secure.call(&Player::update);
secure.call(&Player::takeDamage, 50);

int hp = secure.call(&Player::getHealth);
```

## Build
```bash
g++ -std=c++11 -O2 main.cpp -o vtableenc
```

**Requirements**: C++11 or higher

## Example Output
```
Original state:
vtable pointer: 0x00007ff7cb534658
vtable bytes: 58 46 53 cb f7 7f 00 00

Encrypting vtable...
encrypted vtable: 0x209ed8340e9d3639
encrypted bytes: 39 36 9d 0e 34 d8 9e 20

Decrypting vtable...
decrypted vtable: 0x00007ff7cb534658
```

## Security Benefits

✅ **Memory Scanner Evasion**: Vtable addresses hidden  
✅ **Hook Prevention**: Invalid pointer blocks function hooking  
✅ **Pattern Analysis Protection**: Encrypted pointers appear random  
✅ **Per-Instance Keys**: Different objects = different encrypted values  
✅ **Anti-Tampering**: Modifications result in crashes  

## Use Cases

- Game anti-cheat systems
- Software license protection
- DRM implementations
- Code obfuscation
- Reverse engineering protection

## Technical Details

**Encryption Algorithm:**
1. 64-bit seed generation
2. Key expansion via hash mixing
3. XOR with dynamic key stream
4. Bit rotation (variable shift)
5. Second XOR layer
