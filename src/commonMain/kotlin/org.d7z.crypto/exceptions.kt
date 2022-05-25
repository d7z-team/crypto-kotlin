package org.d7z.crypto

/**
 * 算法初始化错误
 */
open class AlgorithmInitializationException(name: String, message: String = "", exception: Exception? = null) :
    RuntimeException("Algorithm '$name' Error ：$message .", exception)

/**
 * 算法不被支持
 */
class AlgorithmNotSupportException(name: String, message: String = "", exception: Exception? = null) :
    AlgorithmInitializationException(name, " not support , $message", exception)

class AlgorithmBadRequestException(
    name: String,
    errorData: String,
    message: String = "",
    exception: Exception? = null
) : RuntimeException("Algorithm ' $name ' initialization fail :bad request( $errorData ) .$message", exception)
