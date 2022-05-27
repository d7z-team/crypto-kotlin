package org.d7z.crypto

import org.d7z.crypto.factory.IMessageDigest
import org.d7z.crypto.hash.IHash
import org.d7z.crypto.type.MessageDigestType

object MessageDigest : IMessageDigest {
    private val algorithms: Map<String, MessageDigestType> = MessageDigestType.values().map { type ->
        mutableSetOf<String>().apply {
            addAll(
                type.alias.flatMap {
                    listOf(
                        it.uppercase(),
                        it.uppercase().replace("_", "-"),
                        it.uppercase().replace("-", "_"),
                        it.lowercase(),
                        it.lowercase().replace("_", "-"),
                        it.lowercase().replace("-", "_"),
                    )
                }
            )
            addAll(listOf(type.name.uppercase(), type.name.lowercase()))
        } to type
    }.flatMap { d -> d.first.map { it to d.second } }.toMap()

    /**
     * 根据名称获取摘要实现
     *
     * 如果摘要不存在则会抛出 `AlgorithmNotSupportException` 异常
     *
     * @param name String 摘要名称
     * @return IHash 摘要实现
     */
    fun getInstance(name: String): IHash {
        println(algorithms.keys)
        val digestType = algorithms[name] ?: throw AlgorithmNotSupportException(name, "未找到可用的摘要算法")
        return getInstance(digestType)
    }

    override fun getInstance(type: MessageDigestType): IHash {
        return try {
            // 获取摘要算法，如果不存在则回退到平台无关实现
            CryptoPlatform.messageDigest.getInstance(type)
        } catch (e: AlgorithmInitializationException) {
            type.callback
        }
    }
}
