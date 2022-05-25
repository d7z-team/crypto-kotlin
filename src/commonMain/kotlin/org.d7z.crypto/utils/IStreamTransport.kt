package org.d7z.crypto.utils

/**
 * 抽象
 */
interface IStreamTransport {
    fun available(): Boolean
    fun read(container: ByteArray): Int {
        return read(container, 0, container.size)
    }

    fun read(container: ByteArray, offset: Int, size: Int): Int
    fun close()
}
