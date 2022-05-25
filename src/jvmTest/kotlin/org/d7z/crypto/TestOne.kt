package org.d7z.crypto

import org.d7z.crypto.hash.JMD5Hash
import org.d7z.crypto.hash.JSHA1Hash
import org.d7z.crypto.hash.MD5Hash
import org.d7z.crypto.utils.streamTransport
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class TestOne {
    @Test
    fun test() {

        val strs = StringBuilder()
        for (i in 0..1000) {
            strs.append("a")
            val data = strs.toString().toByteArray(Charsets.ISO_8859_1)
            val data1 = BigInteger(1, JMD5Hash().loadHash(data.streamTransport())).toString(16)
            val data2 = BigInteger(1, MD5Hash().loadHash(data.streamTransport())).toString(16)
            assertEquals(data1, data2, "current: ${strs.length}")
        }

        val data = """
            Hello World
            Hello World
            Hello World
        """.trimIndent().toByteArray()
        println("MD5")
        println(JMD5Hash().loadHashToHexText(data.streamTransport()))
        println(BigInteger(1, JMD5Hash().loadHash(data.streamTransport())).toString(16))
        println(BigInteger(1, MD5Hash().loadHash(data.streamTransport())).toString(16))
        println("sha-1")
        println(BigInteger(1, JSHA1Hash().loadHash(data.streamTransport())).toString(16))
    }
}
