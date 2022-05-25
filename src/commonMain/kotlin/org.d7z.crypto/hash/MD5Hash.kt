package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach
import kotlin.math.abs
import kotlin.math.sin

/**
 * MD5算法软实现
 */
class MD5Hash : IHash {
    companion object {
        /**
         * 标准的幻数
         */
        private val constData = longArrayOf(0X67452301, -0x10325477, -0x67452302, 0X10325476)

        /**
         * 位移量seekMatrix,行为轮，总共有4轮，列为每轮中的一次循环，总共16次
         */
        private val seekMatrix: Array<Array<Long>> = arrayOf(
            arrayOf(7, 12, 17, 22),
            arrayOf(5, 9, 14, 20),
            arrayOf(4, 11, 16, 23),
            arrayOf(6, 10, 15, 21),
        )
        private val constMatrix: LongArray = kotlin.run {
            val result = LongArray(64)
            for ((index, _) in result.withIndex()) {
                val i = index + 1
                result[index] = (abs(sin(i.toDouble())) * 4294967296L).toLong()
            }
            result
        }
    }

    override fun loadHash(source: IStreamTransport): ByteArray {
        val result = constData.copyOf()
        var sourceSize: Long = 0
        val group = LongArray(16)
        val endBuffer = ByteArray(64)
        source.bufferEach(64) { buffer, bufferSize ->
            sourceSize += bufferSize
            if (bufferSize == 64) {
                // 可完整切片的数据
                wrapGroup(buffer, group)
                transfer(group, result)
            } else {
                // 不可完整切片的数据,为末尾数据
                buffer.copyInto(endBuffer, 0, 0, bufferSize)
            }
        }
        val endSize = (sourceSize % 64).toInt()
        if (endSize < 56) {
            endBuffer[endSize] = (1 shl 7).toByte()
            for (i in 1 until 56 - endSize) {
                endBuffer[endSize + i] = 0
            }
        } else {
            endBuffer[endSize] = (1 shl 7).toByte()
            for (i in endSize + 1..63) endBuffer[i] = 0
            wrapGroup(endBuffer, group)
            transfer(group, result) // 处理分组
            for (i in 0..55) endBuffer[i] = 0
        }
        var len = (sourceSize shl 3)
        for (i in 0..7) {
            endBuffer[56 + i] = (len and 0xFFL).toByte()
            len = len shr 8
        }
        wrapGroup(endBuffer, group)
        transfer(group, result)
        val resultTempBytes = ByteArray(4)
        return result.flatMap {
            var data = it
            for ((i, _) in resultTempBytes.withIndex()) {
                resultTempBytes[i] = (data and 0xFF).toByte()
                data = data shr 8
            }
            resultTempBytes.toList()
        }.toByteArray()
    }

    private fun wrapGroup(container: ByteArray, tempBytes: LongArray) {
        for (i in 0 until 16) {
            tempBytes[i] = container[4 * i].toUByte().toLong() or (
                container[4 * i + 1].toUByte().toLong() shl 8
                ) or (
                container[4 * i + 2].toUByte().toLong() shl 16
                ) or (
                container[4 * i + 3].toUByte().toLong() shl 24
                )
        }
    }

    /**
     * 主要的操作，四轮循环
     * @param groups--每一个分组512位（64字节）
     */
    private fun transfer(groups: LongArray, result: LongArray) {
        var a = result[0]
        var b = result[1]
        var c = result[2]
        var d = result[3]
        a = function1(a, b, c, d, groups[0], seekMatrix[0][0], constMatrix[0])
        d = function1(d, a, b, c, groups[1], seekMatrix[0][1], constMatrix[1])
        c = function1(c, d, a, b, groups[2], seekMatrix[0][2], constMatrix[2])
        b = function1(b, c, d, a, groups[3], seekMatrix[0][3], constMatrix[3])
        a = function1(a, b, c, d, groups[4], seekMatrix[0][0], constMatrix[4])
        d = function1(d, a, b, c, groups[5], seekMatrix[0][1], constMatrix[5])
        c = function1(c, d, a, b, groups[6], seekMatrix[0][2], constMatrix[6])
        b = function1(b, c, d, a, groups[7], seekMatrix[0][3], constMatrix[7])
        a = function1(a, b, c, d, groups[8], seekMatrix[0][0], constMatrix[8])
        d = function1(d, a, b, c, groups[9], seekMatrix[0][1], constMatrix[9])
        c = function1(c, d, a, b, groups[10], seekMatrix[0][2], constMatrix[10])
        b = function1(b, c, d, a, groups[11], seekMatrix[0][3], constMatrix[11])
        a = function1(a, b, c, d, groups[12], seekMatrix[0][0], constMatrix[12])
        d = function1(d, a, b, c, groups[13], seekMatrix[0][1], constMatrix[13])
        c = function1(c, d, a, b, groups[14], seekMatrix[0][2], constMatrix[14])
        b = function1(b, c, d, a, groups[15], seekMatrix[0][3], constMatrix[15])

        a = function2(a, b, c, d, groups[1], seekMatrix[1][0], constMatrix[16])
        d = function2(d, a, b, c, groups[6], seekMatrix[1][1], constMatrix[17])
        c = function2(c, d, a, b, groups[11], seekMatrix[1][2], constMatrix[18])
        b = function2(b, c, d, a, groups[0], seekMatrix[1][3], constMatrix[19])
        a = function2(a, b, c, d, groups[5], seekMatrix[1][0], constMatrix[20])
        d = function2(d, a, b, c, groups[10], seekMatrix[1][1], constMatrix[21])
        c = function2(c, d, a, b, groups[15], seekMatrix[1][2], constMatrix[22])
        b = function2(b, c, d, a, groups[4], seekMatrix[1][3], constMatrix[23])
        a = function2(a, b, c, d, groups[9], seekMatrix[1][0], constMatrix[24])
        d = function2(d, a, b, c, groups[14], seekMatrix[1][1], constMatrix[25])
        c = function2(c, d, a, b, groups[3], seekMatrix[1][2], constMatrix[26])
        b = function2(b, c, d, a, groups[8], seekMatrix[1][3], constMatrix[27])
        a = function2(a, b, c, d, groups[13], seekMatrix[1][0], constMatrix[28])
        d = function2(d, a, b, c, groups[2], seekMatrix[1][1], constMatrix[29])
        c = function2(c, d, a, b, groups[7], seekMatrix[1][2], constMatrix[30])
        b = function2(b, c, d, a, groups[12], seekMatrix[1][3], constMatrix[31])

        a = function3(a, b, c, d, groups[5], seekMatrix[2][0], constMatrix[32])
        d = function3(d, a, b, c, groups[8], seekMatrix[2][1], constMatrix[33])
        c = function3(c, d, a, b, groups[11], seekMatrix[2][2], constMatrix[34])
        b = function3(b, c, d, a, groups[14], seekMatrix[2][3], constMatrix[35])
        a = function3(a, b, c, d, groups[1], seekMatrix[2][0], constMatrix[36])
        d = function3(d, a, b, c, groups[4], seekMatrix[2][1], constMatrix[37])
        c = function3(c, d, a, b, groups[7], seekMatrix[2][2], constMatrix[38])
        b = function3(b, c, d, a, groups[10], seekMatrix[2][3], constMatrix[39])
        a = function3(a, b, c, d, groups[13], seekMatrix[2][0], constMatrix[40])
        d = function3(d, a, b, c, groups[0], seekMatrix[2][1], constMatrix[41])
        c = function3(c, d, a, b, groups[3], seekMatrix[2][2], constMatrix[42])
        b = function3(b, c, d, a, groups[6], seekMatrix[2][3], constMatrix[43])
        a = function3(a, b, c, d, groups[9], seekMatrix[2][0], constMatrix[44])
        d = function3(d, a, b, c, groups[12], seekMatrix[2][1], constMatrix[45])
        c = function3(c, d, a, b, groups[15], seekMatrix[2][2], constMatrix[46])
        b = function3(b, c, d, a, groups[2], seekMatrix[2][3], constMatrix[47])

        a = function4(a, b, c, d, groups[0], seekMatrix[3][0], constMatrix[48])
        d = function4(d, a, b, c, groups[7], seekMatrix[3][1], constMatrix[49])
        c = function4(c, d, a, b, groups[14], seekMatrix[3][2], constMatrix[50])
        b = function4(b, c, d, a, groups[5], seekMatrix[3][3], constMatrix[51])
        a = function4(a, b, c, d, groups[12], seekMatrix[3][0], constMatrix[52])
        d = function4(d, a, b, c, groups[3], seekMatrix[3][1], constMatrix[53])
        c = function4(c, d, a, b, groups[10], seekMatrix[3][2], constMatrix[54])
        b = function4(b, c, d, a, groups[1], seekMatrix[3][3], constMatrix[55])
        a = function4(a, b, c, d, groups[8], seekMatrix[3][0], constMatrix[56])
        d = function4(d, a, b, c, groups[15], seekMatrix[3][1], constMatrix[57])
        c = function4(c, d, a, b, groups[6], seekMatrix[3][2], constMatrix[58])
        b = function4(b, c, d, a, groups[13], seekMatrix[3][3], constMatrix[59])
        a = function4(a, b, c, d, groups[4], seekMatrix[3][0], constMatrix[60])
        d = function4(d, a, b, c, groups[11], seekMatrix[3][1], constMatrix[61])
        c = function4(c, d, a, b, groups[2], seekMatrix[3][2], constMatrix[62])
        b = function4(b, c, d, a, groups[9], seekMatrix[3][3], constMatrix[63])

        result[0] += a
        result[1] += b
        result[2] += c
        result[3] += d
        result[0] = result[0] and 0xFFFFFFFFL
        result[1] = result[1] and 0xFFFFFFFFL
        result[2] = result[2] and 0xFFFFFFFFL
        result[3] = result[3] and 0xFFFFFFFFL
    }

    private fun function1(a: Long, b: Long, c: Long, d: Long, M: Long, s: Long, K: Long): Long {
        var first = a
        first += ((b and c or (b.inv() and d)) and 0xFFFFFFFFL) + M + K
        first = first and 0xFFFFFFFFL shl s.toInt() or (first and 0xFFFFFFFFL ushr (32 - s).toInt())
        first += b
        return first and 0xFFFFFFFFL
    }

    private fun function2(a: Long, b: Long, c: Long, d: Long, M: Long, s: Long, K: Long): Long {
        var first = a
        first += ((b and d or (c and d.inv())) and 0xFFFFFFFFL) + M + K
        first = first and 0xFFFFFFFFL shl s.toInt() or (first and 0xFFFFFFFFL ushr (32 - s).toInt())
        first += b
        return first and 0xFFFFFFFFL
    }

    private fun function3(a: Long, b: Long, c: Long, d: Long, M: Long, s: Long, K: Long): Long {
        var first = a
        first += ((b xor c xor d) and 0xFFFFFFFFL) + M + K
        first = first and 0xFFFFFFFFL shl s.toInt() or (first and 0xFFFFFFFFL ushr (32 - s).toInt())
        first += b
        return first and 0xFFFFFFFFL
    }

    private fun function4(a: Long, b: Long, c: Long, d: Long, M: Long, s: Long, K: Long): Long {
        var first = a
        first += ((c xor (b or d.inv())) and 0xFFFFFFFFL) + M + K
        first = first and 0xFFFFFFFFL shl s.toInt() or (first and 0xFFFFFFFFL ushr (32 - s).toInt())
        first += b
        return first and 0xFFFFFFFFL
    }
}
