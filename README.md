# [DEV] Crypto Kotlin MP

> 一个简单的加密模块，真正开发中 ...

## 特性

- 使用简单
- 所有算法带有平台无关实现

**注意**：如果你的项目只运行在 Java 环境下，请使用 [Legion of the Bouncy Castle](https://www.bouncycastle.org/)
项目，他能提供更好的性能和安全性。所有平台无关实现未经过安全审核和性能优化，请谨慎使用。

## 支持的算法

<details>
  <summary><b>摘要算法</b></summary>

- [X] MD5
- [X] SHA-1
- [X] SHA-2
  - [X] SHA-224
  - [X] SHA-256
  - [X] SHA-384
  - [X] SHA-512
  - [X] SHA-512/224
  - [X] SHA-512/256
- [X] SHA-3
  - [X] KECCAK-224
  - [X] KECCAK-256
  - [X] KECCAK-384
  - [X] KECCAK-512
  - [X] SHA3-224
  - [X] SHA3-256
  - [X] SHA3-384
  - [X] SHA3-512
  - [X] SHAKE-128
  - [X] SHAKE-256
- [ ] Blake
- [ ] Blake2
- [ ] Blake3
- [ ] SM3
- [X] CRC32

</details>

<details>
  <summary><b>对称加密算法</b></summary>

- [ ] AES
- [ ] ChaCha20

</details>


<details>
  <summary><b>非对称加密算法</b></summary>

- [ ] RSA
- [ ] P-256
- [ ] P-384
- [ ] P-521
- [ ] Curve25519
- [ ] Curve448
- [ ] SM2

</details>
## 快速开始

// TODO

## 更新日志

// TODO

## 致谢

- 项目部分加密算法参考自 [noise-java 项目](https://github.com/rweather/noise-java)
  和 [OpenJDK 项目](https://github.com/openjdk/jdk/tree/master/src/java.base/share/classes/sun/security)
- 项目使用的 `BigInteger` 由 [Kotlin MP BigNum library
  ](https://github.com/ionspin/kotlin-multiplatform-bignum) 提供
- `SHA-3` 参考自 [romus/sha](https://github.com/romus/sha)

## LICENSE

项目使用 [GNU General Public License, version 2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
，更多详情请查看 [License文件](./LICENSE)
