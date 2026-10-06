#pragma once

#include "crypto/types.h"

namespace hxv4::crypto {

// Poly1305（RFC 8439）。密钥 = r ‖ s，各 16 字节。
// 用 26 位 limb 实现，避免依赖 __int128（MSVC 上没有）。
class Poly1305 {
public:
    explicit Poly1305(const Key32& key);

    void update(const uint8_t* data, size_t len);
    Tag16 finalize();

private:
    // 处理一个完整 16 字节块。hibit 对完整块是 1<<24，对补零的末块是 0。
    void block(const uint8_t* m, uint32_t hibit);

    uint32_t r_[5];
    uint32_t h_[5];
    uint32_t pad_[4];
    uint8_t buf_[16];
    size_t left_ = 0;
};

// 一次性接口。
Tag16 poly1305(const Key32& key, const uint8_t* msg, size_t len);

}  // namespace hxv4::crypto
