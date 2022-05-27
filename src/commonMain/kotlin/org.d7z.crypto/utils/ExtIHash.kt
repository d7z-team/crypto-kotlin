package org.d7z.crypto.utils

import org.d7z.crypto.hash.IHash
import kotlin.experimental.and

@Suppress("SpellCheckingInspection")
private val hexArr = "0123456789abcdef".toCharArray()

/**
 * 将二进制数据转换成十六进制字符串
 */
fun ByteArray.toHexText(): String {
    val bytes = this
    val hexChars = CharArray(bytes.size * 2)
    for (j in bytes.indices) {
        val value = (bytes[j] and 0xFF.toByte()).toUByte().toInt()
        hexChars[j * 2] = hexArr[value ushr 4]
        hexChars[j * 2 + 1] = hexArr[value and 0x0F]
    }
    return hexChars.joinToString("")
}

/**
 * 计算 byteArray 摘要
 */
fun IHash.digest(bytes: ByteArray): ByteArray {
    return digest(bytes.streamTransport())
}

/**
 * 计算字符串的摘要信息 (UTF-8)
 */
fun IHash.digestText(data: String): String {
    return digest(data.encodeToByteArray()).toHexText()
}
