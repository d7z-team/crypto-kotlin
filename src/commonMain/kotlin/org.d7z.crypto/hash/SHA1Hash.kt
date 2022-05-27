package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach

/**
 * SHA-1 的 Kotlin Common 实现
 *
 * 注意，SHA-1 已被证明不安全，请谨慎使用
 */
class SHA1Hash : IHash {
    private val staticData = longArrayOf(
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    ).map { it.toInt() }.toIntArray()

    override fun digest(source: IStreamTransport): ByteArray {
        // 摘要数据存储数组
        val digestInt = staticData.copyOf()
        val tempDigestInt = digestInt.copyOf()

        // 计算过程中的临时数据存储数组
        val workBlock = IntArray(80)
        val endBuffer = ByteArray(64)
        var sourceSize: Long = 0

        source.bufferEach(64) { buf, size ->
            sourceSize += size
            if (size == 64) {
                fillBlock(buf, workBlock)
                iterate(workBlock, digestInt, tempDigestInt)
            } else {
                // 不可完整切片的数据,为末尾数据
                buf.copyInto(endBuffer, 0, 0, size)
            }
        }
        val endSize = (sourceSize % 64).toInt()
        // 补1操作
        endBuffer[endSize] = 0x80.toByte()
        // 判断末尾是否有足够空间填充数据集大小
        if (endSize < 56) {
            // 清空
            endBuffer.fill(0, endSize + 1, 56)
        } else {
            endBuffer.fill(0, endSize + 1, 64)
            fillBlock(endBuffer, workBlock)
            iterate(workBlock, digestInt, tempDigestInt)
            endBuffer.fill(0, 0, 56)
        }
        val len = sourceSize * 8
        for (i in 0..7) {
            endBuffer[endBuffer.size - 1 - i] = (len ushr 8 * i and 0xFFL).toByte()
        }
        fillBlock(endBuffer, workBlock)
        iterate(workBlock, digestInt, tempDigestInt)

        val digest = ByteArray(20)
        for (i in digestInt.indices) {
            digest[i * 4] = (digestInt[i] ushr 24).toByte()
            digest[i * 4 + 1] = (digestInt[i] ushr 16).toByte()
            digest[i * 4 + 2] = (digestInt[i] ushr 8).toByte()
            digest[i * 4 + 3] = digestInt[i].toByte()
        }
        return digest
    }

    private fun iterate(workBlock: IntArray, digestInt: IntArray, tempDigestInt: IntArray) {
        digestInt.copyInto(tempDigestInt)
        for (j in 0..19) {
            val tmp = f4(tempDigestInt[0], 5) +
                f1(
                    tempDigestInt[1],
                    tempDigestInt[2],
                    tempDigestInt[3]
                ) +
                tempDigestInt[4] +
                workBlock[j] + 0x5a827999
            tempDigestInt[4] = tempDigestInt[3]
            tempDigestInt[3] = tempDigestInt[2]
            tempDigestInt[2] = f4(tempDigestInt[1], 30)
            tempDigestInt[1] = tempDigestInt[0]
            tempDigestInt[0] = tmp
        }
        for (k in 20..39) {
            val tmp = f4(tempDigestInt[0], 5) +
                f2(tempDigestInt[1], tempDigestInt[2], tempDigestInt[3]) + tempDigestInt[4] +
                workBlock[k] + 0x6ed9eba1
            tempDigestInt[4] = tempDigestInt[3]
            tempDigestInt[3] = tempDigestInt[2]
            tempDigestInt[2] = f4(tempDigestInt[1], 30)
            tempDigestInt[1] = tempDigestInt[0]
            tempDigestInt[0] = tmp
        }
        for (l in 40..59) {
            val tmp = f4(tempDigestInt[0], 5) +
                f3(tempDigestInt[1], tempDigestInt[2], tempDigestInt[3]) + tempDigestInt[4] +
                workBlock[l] + 0x8f1bbcdc.toInt()
            tempDigestInt[4] = tempDigestInt[3]
            tempDigestInt[3] = tempDigestInt[2]
            tempDigestInt[2] = f4(tempDigestInt[1], 30)
            tempDigestInt[1] = tempDigestInt[0]
            tempDigestInt[0] = tmp
        }
        for (m in 60..79) {
            val tmp = f4(tempDigestInt[0], 5) +
                f2(tempDigestInt[1], tempDigestInt[2], tempDigestInt[3]) + tempDigestInt[4] +
                workBlock[m] + 0xca62c1d6.toInt()
            tempDigestInt[4] = tempDigestInt[3]
            tempDigestInt[3] = tempDigestInt[2]
            tempDigestInt[2] = f4(tempDigestInt[1], 30)
            tempDigestInt[1] = tempDigestInt[0]
            tempDigestInt[0] = tmp
        }
        for (i2 in tempDigestInt.indices) {
            digestInt[i2] = digestInt[i2] + tempDigestInt[i2]
        }
    }

    /**
     * 从原始数据中提取填充摘要
     */
    private fun fillBlock(container: ByteArray, workBlock: IntArray) {
        for (index in 0 until 16) {
            workBlock[index] =
                (container[index * 4].toUByte().toInt() shl 24) or
                (container[index * 4 + 1].toUByte().toInt() shl 16) or
                (container[index * 4 + 2].toUByte().toInt() shl 8) or
                (container[index * 4 + 3].toUByte().toInt())
        }
        // 摘要计算
        for (index in 16 until 80) {
            workBlock[index] = f4(
                workBlock[index - 3] xor workBlock[index - 8] xor workBlock[index - 14] xor
                    workBlock[index - 16],
                1
            )
        }
    }

    private fun f1(x: Int, y: Int, z: Int): Int {
        return x and y or (x.inv() and z)
    }

    private fun f2(x: Int, y: Int, z: Int): Int {
        return x xor y xor z
    }

    private fun f3(x: Int, y: Int, z: Int): Int {
        return (x and y) or (x and z) or (y and z)
    }

    private fun f4(x: Int, y: Int): Int {
        return (x shl y) or (x ushr (32 - y))
    }
}
