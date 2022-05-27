package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport

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
}
