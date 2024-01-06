#include "tinyotp_totp.h"
#include "tinyotp_sha1.h"

namespace tinyotp {

totp::totp(const void* key, int len, unsigned long long seconds)
{
    m_key.assign((unsigned char*)key, ((unsigned char*)key) + len);
    m_seconds = seconds;
}

unsigned int totp::get_code(unsigned long long ts)
{
    auto steps = ts / m_seconds;
    return get_code_by_step(steps);
}

unsigned int totp::get_code_by_step(unsigned long long step)
{
    // STEP 0, map the number of steps in a 8-bytes array (counter value)
    unsigned char _byteArray[8];
    for (int i = 7; i >= 0; --i) {
        _byteArray[i] = (unsigned char)(step & 0xFF);
        step >>= 8;
    }

    // STEP 1, get the HMAC-SHA1 hash from counter and key
    tinyotp::sha1 the_sha1;
    the_sha1.init_hmac(m_key.data(), (unsigned char)m_key.size());
    the_sha1.write_array(_byteArray, 8);
    unsigned char* _hash = the_sha1.result_hmac();

    // STEP 2, apply dynamic truncation to obtain a 4-bytes string
    unsigned int _truncatedHash = 0;
    unsigned char _offset = _hash[20 - 1] & 0xF;
    unsigned char j;
    for (j = 0; j < 4; ++j) {
        _truncatedHash <<= 8;
        _truncatedHash |= _hash[_offset + j];
    }

    // STEP 3, compute the OTP value
    _truncatedHash &= 0x7FFFFFFF;    //Disabled
    _truncatedHash %= 1000000;

    return _truncatedHash;
}

} // end of namespace tinyotp
