package agno

@Suppress("MemberVisibilityCanBePrivate", "unused")
data class BitByte(
  val uByte: UByte
) {
  constructor(number: Int) : this((number and 0xFF).toUByte())

  /** i=0 means least significant bit; i=7 means most */
  operator fun get(i: Int): Boolean = when {
    i in 0..7 -> (uByte and (0b1 shl i).toUByte()) > 0u
    else -> error("Only indices 0-7 are legal")
  }

  infix fun and(other: BitByte): BitByte = shloop(other) { a, b -> a and b }

  infix fun or(other: BitByte): BitByte = shloop(other) { a, b -> a or b }

  infix fun xor(other: BitByte): BitByte = shloop(other) { a, b -> a != b }

  fun not(): BitByte = plosh { !it }

  private fun plosh(bitMethod: (Boolean) -> Boolean): BitByte {
    var newN = 0
    for (i in 7 downTo 0) {
      newN *= 0b10
      if (bitMethod(this[i])) newN++
    }
    return BitByte(newN)
  }

  private fun shloop(other: BitByte, bitMethod: (Boolean, Boolean) -> Boolean): BitByte {
    var newN = 0
    for (i in 7 downTo 0) {
      newN *= 0b10
      if (bitMethod(this[i], other[i])) newN++
    }
    return BitByte(newN)
  }


  infix fun rotateRight(bitCount: Int): BitByte = BitByte(uByte.rotateRight(bitCount))

  infix fun rotateLeft(bitCount: Int): BitByte = BitByte(uByte.rotateLeft(bitCount))

  infix fun shiftRight(bitCount: Int): BitByte = shiftRight(bitCount, ZERO)

  fun shiftRight(bitCount: Int, fill: BitByte): BitByte {
    val glued = fill.toInt() * 0b100 + this.toInt()
    return BitByte(glued shr bitCount)
  }

  infix fun shiftLeft(bitCount: Int): BitByte = shiftLeft(bitCount, ZERO)

  fun shiftLeft(bitCount: Int, fill: BitByte): BitByte {
    val glued = this.toInt() * 0b100 + fill.toInt()
    return BitByte((glued shl bitCount) shr 8)
  }

  fun toByte(): Byte = uByte.toByte()

  /** Returned int is unsigned, between 0 and 255 */
  fun toInt(): Int = uByte.toInt()

  fun bitSum(): Int = uByte.countOneBits()

  override fun toString(): String =
    "BitByte(${toBinString()})"

  fun toBinString(): String =
    (7 downTo 0).joinToString(separator = "") {
      if (this[it]) "1" else "0"
    }

  fun toHexString(): String {
    val hex = uByte.toString(16)
    return "00$hex".takeLast(2)
  }

  companion object {
    val ZERO = BitByte(0)
    val FULL = BitByte(0xFF)

    fun List<BitByte>.toByteString(): String =
      this.toByteArray().toString(Consts.CHARSET)

    private fun List<BitByte>.toByteArray(): ByteArray =
      this.map { it.toByte() }.toByteArray()

    infix fun List<BitByte>.xor(other: List<BitByte>): List<BitByte> =
      if (this.size == other.size) {
        this.zip(other).map { it.first xor it.second }
      } else error("Lists have to have similar lengths (${this.size} vs ${other.size})")
  }
}
