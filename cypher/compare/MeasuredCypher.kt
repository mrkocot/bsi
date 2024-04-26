package compare

abstract class MeasuredCypher<KeyType> {
  private var key: KeyType? = null

  abstract val name: String

  fun generateKey(): Long = measured {
    key = doGenerateKey()
  }.nanos

  /** Does not actually initialise the key, only measures generation length */
  fun measureNGenerations(n: Int): Long = measured {
    repeat(n) { doGenerateKey() }
  }.nanos

  fun encode(plainText: ByteArray): Result<ByteArray> = measured {
    doEncode(plainText)
  }

  fun decode(cypherText: ByteArray): Result<ByteArray> = measured {
    doDecode(cypherText)
  }

  protected fun getKey(): KeyType = key ?: error("Key not initialised")

  protected abstract fun doGenerateKey(): KeyType

  protected abstract fun doEncode(plainText: ByteArray): ByteArray

  protected abstract fun doDecode(cypherText: ByteArray): ByteArray

  private fun <T> Long.toResult(value: T): Result<T> =
    Result(time() - this, value)

  private fun <T> measured(operation: () -> T): Result<T> {
    val start = time()
    val result = operation()
    return start.toResult(result)
  }

  data class Result<T> (
    val nanos: Long,
    val value: T,
  )
}

private fun time() = System.nanoTime()
