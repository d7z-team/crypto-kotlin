package org.d7z.crypto

class SHA1 {
    private val staticData = intArrayOf(
        0x67452301, 0xefcdab89.toInt(), 0x98badcfe.toInt(), 0x10325476, 0xc3d2e1f0.toInt()
    )

    // 格式化输入字节数组格式
    private fun byteArrayFormatData(byteData: ByteArray): ByteArray {
        // 补0数量
        var zeros = 0
        // 补位后总位数
        var size = 0
        // 原始数据长度
        val n = byteData.size
        // 模64后的剩余位数
        val m = n % 64
        // 计算添加0的个数以及添加10后的总长度
        if (m < 56) {
            zeros = 55 - m
            size = n - m + 64
        } else if (m == 56) {
            zeros = 63
            size = n + 8 + 64
        } else {
            zeros = 63 - m + 56
            size = n + 64 - m + 64
        }
        // 补位后生成的新数组内容
        val newByte = ByteArray(size)
        // 复制数组的前面部分
        System.arraycopy(byteData, 0, newByte, 0, n)
        // 获得数组Append数据元素的位置
        var l = n
        // 补1操作
        newByte[l++] = 0x80.toByte()
        // 补0操作
        for (i in 0 until zeros) {
            newByte[l++] = 0x00.toByte()
        }
        // 计算数据长度，补数据长度位共8字节，长整型
        val N = n.toLong() * 8
        newByte[l++] = 0
        newByte[l++] = 0
        newByte[l++] = 0
        newByte[l++] = (N shr 32 and 0xFFL).toByte()
        newByte[l++] = (N shr 24 and 0xFFL).toByte()
        newByte[l++] = (N shr 16 and 0xFFL).toByte()
        newByte[l++] = (N shr 8 and 0xFFL).toByte()
        newByte[l] = (N and 0xFFL).toByte()
        return newByte
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

    // 计算sha-1摘要，返回相应的字节数组
    fun getDigestOfBytes(byteData: ByteArray): ByteArray {
        // 摘要数据存储数组
        val digestInt = staticData.clone()
        // 计算过程中的临时数据存储数组
        val tmpData = IntArray(80)
        // 初试化常量
        // 格式化输入字节数组，补10及长度数据
        val newByte = byteArrayFormatData(byteData)
        // 获取数据摘要计算的数据单元个数
        val count = newByte.size / 64
        // 循环对每个数据单元进行摘要计算
        for (pos in 0 until count) {
            // 将每个单元的数据转换成16个整型数据，并保存到tmpData的前16个数组元素中
            for (j in 0..15) {
                val index = pos * 64 + j * 4
                tmpData[j] =
                    newByte[index].toUByte().toInt() and 0xff shl 24 or
                    (newByte[index + 1].toUByte().toInt() and 0xff shl 16) or
                    (newByte[index + 2].toUByte().toInt() and 0xff shl 8) or
                    (newByte[index + 3].toUByte().toInt() and 0xff)
            }
            // 摘要计算函数
            for (i in 16..79) {
                tmpData[i] = f4(
                    tmpData[i - 3] xor tmpData[i - 8] xor tmpData[i - 14] xor
                        tmpData[i - 16],
                    1
                )
            }
            val tempStaticData = IntArray(5)
            System.arraycopy(digestInt, 0, tempStaticData, 0, tempStaticData.size)
            for (j in 0..19) {
                val tmp = f4(tempStaticData[0], 5) +
                    f1(
                        tempStaticData[1],
                        tempStaticData[2],
                        tempStaticData[3]
                    ) +
                    tempStaticData[4] +
                    tmpData[j] + 0x5a827999
                tempStaticData[4] = tempStaticData[3]
                tempStaticData[3] = tempStaticData[2]
                tempStaticData[2] = f4(tempStaticData[1], 30)
                tempStaticData[1] = tempStaticData[0]
                tempStaticData[0] = tmp
            }
            for (k in 20..39) {
                val tmp = f4(tempStaticData[0], 5) +
                    f2(tempStaticData[1], tempStaticData[2], tempStaticData[3]) + tempStaticData[4] +
                    tmpData[k] + 0x6ed9eba1
                tempStaticData[4] = tempStaticData[3]
                tempStaticData[3] = tempStaticData[2]
                tempStaticData[2] = f4(tempStaticData[1], 30)
                tempStaticData[1] = tempStaticData[0]
                tempStaticData[0] = tmp
            }
            for (l in 40..59) {
                val tmp = f4(tempStaticData[0], 5) +
                    f3(tempStaticData[1], tempStaticData[2], tempStaticData[3]) + tempStaticData[4] +
                    tmpData[l] + 0x8f1bbcdc.toInt()
                tempStaticData[4] = tempStaticData[3]
                tempStaticData[3] = tempStaticData[2]
                tempStaticData[2] = f4(tempStaticData[1], 30)
                tempStaticData[1] = tempStaticData[0]
                tempStaticData[0] = tmp
            }
            for (m in 60..79) {
                val tmp = f4(tempStaticData[0], 5) +
                    f2(tempStaticData[1], tempStaticData[2], tempStaticData[3]) + tempStaticData[4] +
                    tmpData[m] + 0xca62c1d6.toInt()
                tempStaticData[4] = tempStaticData[3]
                tempStaticData[3] = tempStaticData[2]
                tempStaticData[2] = f4(tempStaticData[1], 30)
                tempStaticData[1] = tempStaticData[0]
                tempStaticData[0] = tmp
            }
            for (i2 in tempStaticData.indices) {
                digestInt[i2] = digestInt[i2] + tempStaticData[i2]
            }
        }
        val digest = ByteArray(20)
        for (i in digestInt.indices) {
            digest[i * 4] = (digestInt[i] ushr 24).toByte()
            digest[i * 4 + 1] = (digestInt[i] ushr 16).toByte()
            digest[i * 4 + 2] = (digestInt[i] ushr 8).toByte()
            digest[i * 4 + 3] = digestInt[i].toByte()
        }
        return digest
    }
}
