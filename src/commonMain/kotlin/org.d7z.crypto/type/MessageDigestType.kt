package org.d7z.crypto.type

import org.d7z.crypto.hash.IHash
import org.d7z.crypto.hash.MD5Hash
import org.d7z.crypto.hash.SHA1Hash
import org.d7z.crypto.hash.SHA2Hash
import org.d7z.crypto.hash.SHA3Hash

enum class MessageDigestType(val callback: IHash, vararg val alias: String) {
    MD5(MD5Hash()),
    SHA_1(SHA1Hash(), "sha1"),
    SHA_2_224(SHA2Hash(SHA2Type.SHA_224), "sha-256"),
    SHA_2_256(SHA2Hash(SHA2Type.SHA_256), "sha-256"),
    SHA_2_384(SHA2Hash(SHA2Type.SHA_384), "sha-384"),
    SHA_2_512(SHA2Hash(SHA2Type.SHA_512), "sha-512"),
    SHA_2_512_224(SHA2Hash(SHA2Type.SHA_512_224), "sha-512/224", "sha-512-224"),
    SHA_2_512_256(SHA2Hash(SHA2Type.SHA_512_256), "sha-512/256", "sha-512-256"),
    SHA_3_KECCAK_224(SHA3Hash(SHA3Type.KECCAK_224), "sha3-keccak-224", "keccak-224"),
    SHA_3_KECCAK_256(SHA3Hash(SHA3Type.KECCAK_256), "sha3-keccak-256", "keccak-256"),
    SHA_3_KECCAK_384(SHA3Hash(SHA3Type.KECCAK_384), "sha3-keccak-384", "keccak-384"),
    SHA_3_KECCAK_512(SHA3Hash(SHA3Type.KECCAK_512), "sha3-keccak-512", "keccak-512"),
    SHA_3_224(SHA3Hash(SHA3Type.SHA3_224), "sha3-224"),
    SHA_3_256(SHA3Hash(SHA3Type.SHA3_256), "sha3-256"),
    SHA_3_384(SHA3Hash(SHA3Type.SHA3_384), "sha3-384"),
    SHA_3_512(SHA3Hash(SHA3Type.SHA3_512), "sha3-512"),
    SHA_3_SHAKE_128(SHA3Hash(SHA3Type.SHAKE_128), "sha3-shake-128", "shake-128"),
    SHA_3_SHAKE_256(SHA3Hash(SHA3Type.SHAKE_256), "sha3-shake-256", "shake-256"),
}
