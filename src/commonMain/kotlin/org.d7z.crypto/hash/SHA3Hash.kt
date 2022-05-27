package org.d7z.crypto.hash

import com.ionspin.kotlin.bignum.integer.BigInteger
import org.d7z.crypto.type.SHA3Type
import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach

class SHA3Hash(private val type: SHA3Type) : IHash {

    override fun digest(source: IStreamTransport): ByteArray {
        val uState = IntArray(200)
        val rateInBytes = type.rate / 8
        var blockSize = 0
        var inputOffset = 0
        source.bufferEach { buf, size ->
            blockSize = size.coerceAtMost(rateInBytes)
            for (i in 0 until blockSize) {
                uState[i] = (uState[i] xor (buf[i].toInt() and 0xFF))
            }
            inputOffset += blockSize
            if (blockSize == rateInBytes) {
                fillBlock(uState)
                blockSize = 0
            }
        }
        uState[blockSize] = uState[blockSize] xor type.delimit
        if (type.delimit and 0x80 != 0 && blockSize == rateInBytes - 1) {
            fillBlock(uState)
        }
        uState[rateInBytes - 1] = uState[rateInBytes - 1] xor 0x80
        fillBlock(uState)
        val byteResults = ArrayList<Byte>()
        var tOutputLen = type.outputLen / 8
        while (tOutputLen > 0) {
            blockSize = tOutputLen.coerceAtMost(rateInBytes)
            for (i in 0 until blockSize) {
                byteResults.add(uState[i].toByte())
            }
            tOutputLen -= blockSize
            if (tOutputLen > 0) {
                fillBlock(uState)
            }
        }
        return byteResults.toByteArray()
    }

    private fun fillBlock(uState: IntArray) {
        val lState =
            Array(5) {
                arrayOf(
                    BigInteger(0),
                    BigInteger(0),
                    BigInteger(0),
                    BigInteger(0),
                    BigInteger(0)
                )
            }
        for (i in 0..4) {
            for (j in 0..4) {
                val data = IntArray(8)
                val offset = 8 * (i + 5 * j)
                uState.copyInto(data, 0, offset, offset + data.size)
                var uLong = BigInteger(0)
                for (k in 0..7) {
                    uLong = uLong.add(BigInteger(data[k]).shl(8 * k))
                }
                lState[i][j] = uLong
            }
        }
        roundB(lState)
        uState.fill(0)
        for (i in 0..4) {
            for (j in 0..4) {
                val uLong = lState[i][j]
                val data = IntArray(8)
                val mod256 = BigInteger(256)
                for (k in 0..7) {
                    data[k] = uLong.shr(8 * k).mod(mod256).intValue(false)
                }
                val offset = 8 * (i + 5 * j)
                data.copyInto(uState, offset, 0, data.size)
            }
        }
    }

    /**
     * Permutation on the given state.
     *
     * @param state state
     */
    private fun roundB(state: Array<Array<BigInteger>>) {
        var lFState = 1
        for (round in 0..23) {
            val containerA = arrayOf(
                BigInteger(0),
                BigInteger(0),
                BigInteger(0),
                BigInteger(0),
                BigInteger(0)
            )
            val containerB = arrayOf(
                BigInteger(0),
                BigInteger(0),
                BigInteger(0),
                BigInteger(0),
                BigInteger(0)
            )

            // θ step
            for (i in 0..4) {
                containerA[i] = state[i][0]
                    .xor(state[i][1]).xor(state[i][2]).xor(state[i][3]).xor(state[i][4])
            }
            for (i in 0..4) {
                containerB[i] = containerA[(i + 4) % 5].xor(leftRotate64(containerA[(i + 1) % 5], 1))
            }
            for (i in 0..4) {
                for (j in 0..4) {
                    state[i][j] = state[i][j].xor(containerB[i])
                }
            }

            // ρ and π steps
            var x = 1
            var y = 0
            var current = state[x][y]
            for (i in 0..23) {
                val tX = x
                x = y
                y = (2 * tX + 3 * y) % 5
                val shiftValue = current
                current = state[x][y]
                state[x][y] = leftRotate64(shiftValue, (i + 1) * (i + 2) / 2)
            }

            // χ step
            for (j in 0..4) {
                val t = arrayOfNulls<BigInteger>(5)
                for (i in 0..4) {
                    t[i] = state[i][j]
                }
                for (i in 0..4) {
                    // ~t[(i + 1) % 5]
                    val invertVal = t[(i + 1) % 5]!!.xor(STATIC_BIT_64)
                    // t[i] ^ ((~t[(i + 1) % 5]) & t[(i + 2) % 5])
                    state[i][j] = t[i]!!.xor(invertVal.and(t[(i + 2) % 5]!!))
                }
            }

            // ι step
            for (i in 0..6) {
                lFState = ((lFState shl 1) xor ((lFState shr 7) * 0x71)) % 256
                // pow(2, i) - 1
                val bitPosition = (1 shl i) - 1
                if (lFState and 2 != 0) {
                    state[0][0] = state[0][0].xor(BigInteger(1).shl(bitPosition))
                }
            }
        }
    }

    private fun leftRotate64(value: BigInteger, rotate: Int): BigInteger {
        val lp = value.shr(64 - rotate % 64)
        val rp = value.shl(rotate % 64)
        return lp.add(rp).mod(BigInteger.parseString("18446744073709551616", 10))
    }

    companion object {
        private val STATIC_BIT_64 = BigInteger.parseString("18446744073709551615", 10)
    }
}
