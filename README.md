tinyotp
====================

最简单实用的C++ TOTP算法实现

基于：https://github.com/Netthaw/TOTP-MCU



## 示例：

```c++
#include "tinyotp_totp.h"

int main()
{
    char key[] = "f79fa56a4cc1";
    tinyotp::totp otp(key, strlen(key), 60);
    unsigned int code0 = otp.get_code(_time64(nullptr));
    unsigned int code1 = otp.get_code_by_step(1);
    return 0;
}
```



## 编译：

将以下4个文件，加入工程中进行编译即可，无其它依赖。

```
tinyotp_sha1.cpp
tinyotp_sha1.h
tinyotp_totp.cpp
tinyotp_totp.h
```

