package org.d7z.crypto.hash

import org.d7z.crypto.AlgorithmNotSupportException
import org.d7z.crypto.type.SHA3Type
import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

class JSHA3Hash(type: SHA3Type) : IHash {
    private val algorithm = when (type) {
        SHA3Type.KECCAK_224 -> "KECCAK-224" // 此算法可能未实现
        SHA3Type.KECCAK_256 -> "KECCAK-256" // 此算法可能未实现
        SHA3Type.KECCAK_384 -> "KECCAK-384" // 此算法可能未实现
        SHA3Type.KECCAK_512 -> "KECCAK-512" // 此算法可能未实现
        SHA3Type.SHA3_224 -> "SHA3-224"
        SHA3Type.SHA3_256 -> "SHA3-256"
        SHA3Type.SHA3_384 -> "SHA3-384"
        SHA3Type.SHA3_512 -> "SHA3-512"
        SHA3Type.SHAKE_128 -> "SHAKE-128" // 此算法可能未实现
        SHA3Type.SHAKE_256 -> "SHAKE-256" // 此算法可能未实现
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
