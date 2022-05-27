package org.d7z.crypto

import org.d7z.crypto.type.MessageDigestType
import org.d7z.crypto.utils.digestText
import org.junit.jupiter.api.Test

internal class MessageDigestTest {

    @Test
    fun getInstance() {
        println(MessageDigest.getInstance(MessageDigestType.SHA_3_KECCAK_224).digestText("name"))
    }

    @Test
    fun testGetInstance() {
    }
}
