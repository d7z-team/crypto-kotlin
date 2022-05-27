package org.d7z.crypto.hash

import org.d7z.crypto.AlgorithmNotSupportException
import org.d7z.crypto.type.SHA2Type
import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * MD5 Java 后端实现
 */
class JSHA2Hash(type: SHA2Type) : IHash {
    private val algorithm = when (type) {
        SHA2Type.SHA_224 -> "SHA-224"
        SHA2Type.SHA_256 -> "SHA-256"
        SHA2Type.SHA_384 -> "SHA-384"
        SHA2Type.SHA_512 -> "SHA-512"
        SHA2Type.SHA_512_224 -> "SHA-512/224"
        SHA2Type.SHA_512_256 -> "SHA-512/256"
    }

    init {
        try {
            MessageDigest.getInstance(algorithm)
        } catch (e: NoSuchAlgorithmException) {
            throw AlgorithmNotSupportException("$algorithm/Java", "Java 端无法创建对应实现", e)
        }
    }

    override fun digest(source: IStreamTransport): ByteArray {
        val messageDigest = MessageDigest.getInstance(algorithm)
        messageDigest.reset()
        source.bufferEach { buffer, size ->
            messageDigest.update(buffer, 0, size)
        }
        return messageDigest.digest()
    }
}
