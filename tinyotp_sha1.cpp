#include <string.h>
#include "tinyotp_sha1.h"

namespace tinyotp {

#define SHA1_K0   0x5a827999
#define SHA1_K20  0x6ed9eba1
#define SHA1_K40  0x8f1bbcdc
#define SHA1_K60  0xca62c1d6
#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c


static unsigned int rol32(unsigned int number, unsigned char bits) {
    return ((number << bits) | (unsigned int)(number >> (32 - bits)));
}

void sha1::hash_block() {
    unsigned char i;
    unsigned int a, b, c, d, e, t;

    a = m_state.w[0];
    b = m_state.w[1];
    c = m_state.w[2];
    d = m_state.w[3];
    e = m_state.w[4];
    for (i = 0; i < 80; i++) {
        if (i >= 16) {
            t = m_buffer.w[(i + 13) & 15] ^ m_buffer.w[(i + 8) & 15] ^ m_buffer.w[(i + 2) & 15] ^ m_buffer.w[i & 15];
            m_buffer.w[i & 15] = rol32(t, 1);
        }
        if (i < 20) {
            t = (d ^ (b & (c ^ d))) + SHA1_K0;
        }
        else if (i < 40) {
            t = (b ^ c ^ d) + SHA1_K20;
        }
        else if (i < 60) {
            t = ((b & c) | (d & (b | c))) + SHA1_K40;
        }
        else {
            t = (b ^ c ^ d) + SHA1_K60;
        }
        t += rol32(a, 5) + e + m_buffer.w[i & 15];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = t;
    }
    m_state.w[0] += a;
    m_state.w[1] += b;
    m_state.w[2] += c;
    m_state.w[3] += d;
    m_state.w[4] += e;
}

void sha1::add_uncounted(unsigned char data) {
    m_buffer.b[m_buffer_offset ^ 3] = data;
    m_buffer_offset++;
    if (m_buffer_offset == LEN_OF_BLOCK) {
        hash_block();
        m_buffer_offset = 0;
    }
}

void sha1::pad() {
    // Implement SHA-1 padding (fips180-2 ˜5.1.1)

    // Pad with 0x80 followed by 0x00 until the end of the block
    add_uncounted(0x80);
    while (m_buffer_offset != 56) add_uncounted(0x00);

    // Append length in the last 8 bytes
    add_uncounted(0); // We're only using 32 bit lengths
    add_uncounted(0); // But SHA-1 supports 64 bit lengths
    add_uncounted(0); // So zero pad the top bits
    add_uncounted(m_byte_count >> 29); // Shifting to multiply by 8
    add_uncounted(m_byte_count >> 21); // as SHA-1 supports bitstreams as well as
    add_uncounted(m_byte_count >> 13); // byte.
    add_uncounted(m_byte_count >> 5);
    add_uncounted(m_byte_count << 3);
}

void sha1::init() {
    memcpy(m_state.b, m_sha1_init_state, LEN_OF_HASH);
    m_byte_count = 0;
    m_buffer_offset = 0;
}

void sha1::init_hmac(const unsigned char* key, unsigned char keyLength) {
    unsigned char i;
    memset(m_key_buffer, 0, LEN_OF_BLOCK);
    if (keyLength > LEN_OF_BLOCK) {
        // Hash long keys
        init();
        for (; keyLength--;) write(*key++);
        memcpy(m_key_buffer, result(), LEN_OF_HASH);
    }
    else {
        // Block length keys are used as is
        memcpy(m_key_buffer, key, keyLength);
    }
    // Start inner hash
    init();
    for (i = 0; i < LEN_OF_BLOCK; i++) {
        write(m_key_buffer[i] ^ HMAC_IPAD);
    }
}

unsigned char* sha1::result(void) {
    // Pad to complete the last block
    pad();

    // Swap byte order back
    unsigned char i;
    for (i = 0; i < 5; i++) {
        unsigned int a, b;
        a = m_state.w[i];
        b = a << 24;
        b |= (a << 8) & 0x00ff0000;
        b |= (a >> 8) & 0x0000ff00;
        b |= a >> 24;
        m_state.w[i] = b;
    }

    // Return pointer to hash (20 characters)
    return m_state.b;
}

unsigned char* sha1::result_hmac(void) {
    unsigned char i;
    // Complete inner hash
    memcpy(m_inner_hash, result(), LEN_OF_HASH);
    // Calculate outer hash
    init();
    for (i = 0; i < LEN_OF_BLOCK; i++) write(m_key_buffer[i] ^ HMAC_OPAD);
    for (i = 0; i < LEN_OF_HASH; i++) write(m_inner_hash[i]);
    return result();
}

void sha1::write(unsigned char data) {
    ++m_byte_count;
    add_uncounted(data);
    return;
}

void sha1::write_array(unsigned char* buffer, unsigned char size) {
    while (size--) {
        write(*buffer++);
    }
}

} // end of namespace tinyotp
