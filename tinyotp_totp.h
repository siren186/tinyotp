#pragma once
#include <vector>

namespace tinyotp {

class totp {
public:
    /**
     * @brief 初始化TOTP算法
     * @param[in] key 密钥
     * @param[in] len 密钥字节长度
     * @param[in] seconds 每隔多少秒生成一组新密码
     */
    totp(const void* key, int len, unsigned long long seconds);

    /**
     * @brief 根据时间戳，获取一次性密码
     * @param[in] ts 时间戳
     * @return 返回生成的一次性密码
     */
    unsigned int get_code(unsigned long long ts);

    /**
     * @brief 根据步数，获取一次性密码
     * @param[in] step 步数
     * @return 返回生成的一次性密码
     */
    unsigned int get_code_by_step(unsigned long long step);

private:
    std::vector<unsigned char> m_key;
    unsigned long long m_seconds;
};

}
