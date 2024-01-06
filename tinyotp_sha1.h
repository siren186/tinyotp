#pragma once

namespace tinyotp {


class sha1 {
    enum
    {
        LEN_OF_HASH = 20,
        LEN_OF_BLOCK = 64,
    };

public:
    void init();
    void init_hmac(const unsigned char* secret, unsigned char secretLength);
    unsigned char* result(void);
    unsigned char* result_hmac(void);
    void write(unsigned char);
    void write_array(unsigned char* buffer, unsigned char size);

private:
    void hash_block();
    void add_uncounted(unsigned char data);
    void pad();

private:
    union _buffer {
        unsigned char b[LEN_OF_BLOCK];
        unsigned int w[LEN_OF_BLOCK / 4];
    } m_buffer;

    union _state {
        unsigned char b[LEN_OF_HASH];
        unsigned int w[LEN_OF_HASH / 4];
    } m_state;

    unsigned char m_buffer_offset;
    unsigned int m_byte_count;
    unsigned char m_key_buffer[LEN_OF_BLOCK];
    unsigned char m_inner_hash[LEN_OF_HASH];
    const unsigned char m_sha1_init_state[20] = {
      0x01,0x23,0x45,0x67, // H0
      0x89,0xab,0xcd,0xef, // H1
      0xfe,0xdc,0xba,0x98, // H2
      0x76,0x54,0x32,0x10, // H3
      0xf0,0xe1,0xd2,0xc3  // H4
    };
};

}
