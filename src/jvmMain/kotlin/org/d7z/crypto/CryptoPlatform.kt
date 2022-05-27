package org.d7z.crypto

import org.d7z.crypto.factory.IMessageDigest
import org.d7z.crypto.hash.IHash
import org.d7z.crypto.hash.JCRC32Hash
import org.d7z.crypto.hash.JMD5Hash
import org.d7z.crypto.hash.JSHA1Hash
import org.d7z.crypto.hash.JSHA2Hash
import org.d7z.crypto.hash.JSHA3Hash
import org.d7z.crypto.type.MessageDigestType
import org.d7z.crypto.type.SHA2Type
import org.d7z.crypto.type.SHA3Type

actual object CryptoPlatform {
    internal class JMessageDigest : IMessageDigest {
        override fun getInstance(type: MessageDigestType): IHash {
            return when (type) {
                MessageDigestType.CRC32 -> JCRC32Hash()
                MessageDigestType.MD5 -> JMD5Hash()
                MessageDigestType.SHA_1 -> JSHA1Hash()
                MessageDigestType.SHA_2_224 -> JSHA2Hash(SHA2Type.SHA_224)
                MessageDigestType.SHA_2_256 -> JSHA2Hash(SHA2Type.SHA_256)
                MessageDigestType.SHA_2_384 -> JSHA2Hash(SHA2Type.SHA_384)
                MessageDigestType.SHA_2_512 -> JSHA2Hash(SHA2Type.SHA_512)
                MessageDigestType.SHA_2_512_224 -> JSHA2Hash(SHA2Type.SHA_512_224)
                MessageDigestType.SHA_2_512_256 -> JSHA2Hash(SHA2Type.SHA_512_256)
                MessageDigestType.SHA_3_KECCAK_224 -> JSHA3Hash(SHA3Type.KECCAK_224)
                MessageDigestType.SHA_3_KECCAK_256 -> JSHA3Hash(SHA3Type.KECCAK_256)
                MessageDigestType.SHA_3_KECCAK_384 -> JSHA3Hash(SHA3Type.KECCAK_384)
                MessageDigestType.SHA_3_KECCAK_512 -> JSHA3Hash(SHA3Type.KECCAK_512)
                MessageDigestType.SHA_3_224 -> JSHA3Hash(SHA3Type.SHA3_224)
                MessageDigestType.SHA_3_256 -> JSHA3Hash(SHA3Type.SHA3_256)
                MessageDigestType.SHA_3_384 -> JSHA3Hash(SHA3Type.SHA3_384)
                MessageDigestType.SHA_3_512 -> JSHA3Hash(SHA3Type.SHA3_512)
                MessageDigestType.SHA_3_SHAKE_128 -> JSHA3Hash(SHA3Type.SHAKE_128)
                MessageDigestType.SHA_3_SHAKE_256 -> JSHA3Hash(SHA3Type.SHAKE_256)
                else -> throw AlgorithmNotSupportException("$type/Java", "此算法 Java 可能不受支持.")
            }
        }
    }

    actual val messageDigest: IMessageDigest = JMessageDigest()
}
