#include <iostream>
#include <windows.h>
#include "tinyotp_totp.h"

int main()
{
    char key[] = "f79fa56a4cc1";
    tinyotp::totp otp(key, strlen(key), 2);
    unsigned int code0 = otp.get_code(_time64(nullptr));
    unsigned int code1 = otp.get_code_by_step(1);
    return 0;
}
