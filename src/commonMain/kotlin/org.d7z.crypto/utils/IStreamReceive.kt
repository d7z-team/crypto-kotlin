package org.d7z.crypto.utils

/**
 * 抽象
 */
interface IStreamReceive {
    fun write(container: ByteArray): Int
    fun write(container: ByteArray, offset: Int, size: Int): Int
    fun flush()
    fun close()
}
