# Crypto Kotlin MP

> 一个简单的加密模块

## 特性

- 使用简单
- 所有算法带有平台无关实现

## 支持的算法

<details>
  <summary><b>摘要算法</b></summary>

- MD5
- SHA-1
- SHA-2
  - SHA-224
  - SHA-256
  - SHA-384
  - SHA-512
  - SHA-512/224
  - SHA-512/256
- SHA-3
  - KECCAK-224
  - KECCAK-256
  - KECCAK-384
  - KECCAK-512
  - SHA3-224
  - SHA3-256
  - SHA3-384
  - SHA3-512
  - SHAKE-128
  - SHAKE-256
- Blake
- Blake2
- Blake3
- SM3

</details>

## 对称加密算法

- AES
- ChaCha20

## 快速开始

## 更新日志

## 致谢

- 项目部分加密算法参考自 [noise-java 项目](https://github.com/rweather/noise-java)
  和 [OpenJDK 项目](https://github.com/openjdk/jdk/tree/master/src/java.base/share/classes/sun/security)
- 项目使用的 `BigInteger` 由 [Kotlin MP BigNum library
  ](https://github.com/ionspin/kotlin-multiplatform-bignum) 提供
- `SHA-3` 实现参考自 [romus/sha](https://github.com/romus/sha)

## LICENSE

项目使用 [GNU General Public License, version 2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
，更多详情请查看 [License文件](./LICENSE)
