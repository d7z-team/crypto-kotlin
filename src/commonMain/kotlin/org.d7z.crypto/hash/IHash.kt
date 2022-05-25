package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport
import kotlin.experimental.and

/**
 *  哈希抽象函数
 */
interface IHash {
    /**
     * 计算哈希值
     * @param source IStreamTransport 原始数据
     * @return ByteArray 计算结果
     */
    fun digest(source: IStreamTransport): ByteArray

    /**
     * 计算哈希值并转换成16进制串
     *
     * @param source IStreamTransport 原始数据
     * @return String 计算结果
     */
    fun digestHexText(source: IStreamTransport): String {
        val bytes = digest(source)
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val value = (bytes[j] and 0xFF.toByte()).toUByte().toInt()
            hexChars[j * 2] = hexArr[value ushr 4]
            hexChars[j * 2 + 1] = hexArr[value and 0x0F]
        }
        return hexChars.joinToString("")
    }

    companion object {
        @Suppress("SpellCheckingInspection")
        private val hexArr = "0123456789abcdef".toCharArray()
    }
}
