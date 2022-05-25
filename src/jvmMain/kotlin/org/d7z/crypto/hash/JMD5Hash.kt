package org.d7z.crypto.hash

import org.d7z.crypto.AlgorithmNotSupportException
import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * MD5 Java 后端实现
 */
class JMD5Hash : IHash {
    init {
        try {
            MessageDigest.getInstance("MD5")
        } catch (e: NoSuchAlgorithmException) {
            throw AlgorithmNotSupportException("MD5/Java", "Java 端无法创建对应实现", e)
        }
    }

    override fun digest(source: IStreamTransport): ByteArray {
        val messageDigest = MessageDigest.getInstance("MD5")
        source.bufferEach { buffer, size ->
            messageDigest.update(buffer, 0, size)
        }
        return messageDigest.digest()
    }
}
