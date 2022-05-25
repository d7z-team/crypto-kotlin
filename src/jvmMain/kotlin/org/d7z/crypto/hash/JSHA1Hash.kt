package org.d7z.crypto.hash

import org.d7z.crypto.AlgorithmNotSupportException
import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * MD5 Java 后端实现
 */
class JSHA1Hash : IHash {
    init {
        try {
            MessageDigest.getInstance("SHA1")
        } catch (e: NoSuchAlgorithmException) {
            throw AlgorithmNotSupportException("SHA1/Java", "Java 端无法创建对应实现", e)
        }
    }

    override fun loadHash(source: IStreamTransport): ByteArray {
        val messageDigest = MessageDigest.getInstance("SHA1")
        source.bufferEach { buffer, size ->
            messageDigest.update(buffer, 0, size)
        }
        return messageDigest.digest()
    }
}
