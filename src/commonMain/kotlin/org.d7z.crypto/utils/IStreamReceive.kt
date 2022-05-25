package org.d7z.crypto.utils

/**
 * 抽象
 */
interface IStreamReceive {
    fun write(container: ByteArray)
    fun write(container: ByteArray, offset: Int, size: Int)
    fun flush()
    fun close()
}
