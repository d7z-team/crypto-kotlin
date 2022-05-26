package org.d7z.crypto

import org.d7z.crypto.hash.JMD5Hash
import org.d7z.crypto.hash.JSHA1Hash
import org.d7z.crypto.hash.JSHA2Hash
import org.d7z.crypto.hash.MD5Hash
import org.d7z.crypto.hash.SHA1Hash
import org.d7z.crypto.hash.sha2.SHA2V1Hash
import org.d7z.crypto.hash.sha2.SHA2V1Hash.SHA2V1Type
import org.d7z.crypto.type.SHA2Type
import org.d7z.crypto.utils.streamTransport
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class TestOne {
    @Test
    fun test() {

        val data = "Hello World".toByteArray(Charsets.US_ASCII)
        println("MD5")
        println(BigInteger(1, JMD5Hash().digest(data.streamTransport())).toString(16))
        println(BigInteger(1, MD5Hash().digest(data.streamTransport())).toString(16))
        println("sha-1")
        println(BigInteger(1, JSHA1Hash().digest(data.streamTransport())).toString(16))
        println(BigInteger(1, SHA1Hash().digest(data.streamTransport())).toString(16))
        println("sha-224")
        println(BigInteger(1, JSHA2Hash(SHA2Type.SHA_224).digest(data.streamTransport())).toString(16))
        println(BigInteger(1, SHA2V1Hash(SHA2V1Type.SHA_224).digest(data.streamTransport())).toString(16))
        println("sha-256")
        println(BigInteger(1, JSHA2Hash(SHA2Type.SHA_256).digest(data.streamTransport())).toString(16))
        println(BigInteger(1, SHA2V1Hash(SHA2V1Type.SHA_256).digest(data.streamTransport())).toString(16))
    }

    @Test
    fun autoTest() {
        val src = StringBuilder()
        for (i in 0..1000) {
            src.append("a")
            val data = src.toString().toByteArray(Charsets.ISO_8859_1)
            val md5Data1 = BigInteger(1, JMD5Hash().digest(data.streamTransport())).toString(16)
            val md5Data2 = BigInteger(1, MD5Hash().digest(data.streamTransport())).toString(16)
            assertEquals(md5Data1, md5Data2, "current: ${src.length}")
            val shaData1 = BigInteger(1, JSHA1Hash().digest(data.streamTransport())).toString(16)
            val shaData2 = BigInteger(1, SHA1Hash().digest(data.streamTransport())).toString(16)
            assertEquals(shaData1, shaData2, "current: ${src.length}")
            val sha224Data1 = BigInteger(1, JSHA2Hash(SHA2Type.SHA_224).digest(data.streamTransport())).toString(16)
            val sha224Data2 = BigInteger(1, SHA2V1Hash(SHA2V1Type.SHA_224).digest(data.streamTransport())).toString(16)
            assertEquals(sha224Data1, sha224Data2, "current: ${src.length}")
            val sha256Data1 = BigInteger(1, JSHA2Hash(SHA2Type.SHA_256).digest(data.streamTransport())).toString(16)
            val sha256Data2 = BigInteger(1, SHA2V1Hash(SHA2V1Type.SHA_256).digest(data.streamTransport())).toString(16)
            assertEquals(sha256Data1, sha256Data2, "current: ${src.length}")
        }
    }
}
