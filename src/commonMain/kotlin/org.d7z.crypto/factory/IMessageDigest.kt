package org.d7z.crypto.factory

import org.d7z.crypto.hash.IHash
import org.d7z.crypto.type.MessageDigestType

/**
 * 摘要实现工厂
 */
interface IMessageDigest {
    /**
     * 根据摘要类型获取对应摘要，如果无法使用平台相关的摘要则会回退到平台无关的实现
     */
    fun getInstance(type: MessageDigestType): IHash
}
