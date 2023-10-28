class BitByte(
  number: Int
) {
  private val number = (number + 0xFF) % 0xFF

  operator fun get(i: Int): Int = when {
    i < 0 || i >= 8 -> error("Only indices 0-7 are legal")
    else -> (number shr i) and 0b1
  }

  infix fun xor(other: BitByte): BitByte {
    var newN = 0
    repeat(8) {
      newN *= 0b10
      if (this[7-it] != other[7-it]) newN++
    }
    return BitByte(newN)
  }

  fun toByte(): Byte = number.toByte()

  fun bitSum(): Int =
    (0..7).sumOf { this[it] }

  override fun toString(): String = "BitByte($number)"

  companion object {
    fun from(byte: Byte): BitByte = BitByte(byte.toInt())

    fun from(bytes: ByteArray): List<BitByte> =
      bytes.map { from(it) }

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
