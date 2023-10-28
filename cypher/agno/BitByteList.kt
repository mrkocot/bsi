package agno

@Suppress("MemberVisibilityCanBePrivate", "unused")
class BitByteList(private val bitBytes: List<BitByte>) {
  constructor(vararg bitBytes: BitByte) : this(bitBytes.asList())

  val byteN = bitBytes.size
  val bitN = byteN * 8

  fun zip(other: BitByteList, function: (BitByte, BitByte) -> BitByte): BitByteList =
    if (this.byteN == other.byteN) {
      this.toList()
        .zip(other.toList()) { a, b -> function(a, b) }
        .let { BitByteList(it) }
    } else {
      error("Trying to zip BitByteLists with different sizes (${this.byteN} vs ${other.byteN})")
    }

  infix fun and(other: BitByteList): BitByteList = this.zip(other) { a, b -> a and b }

  infix fun or(other: BitByteList): BitByteList = this.zip(other) { a, b -> a or b }

  infix fun xor(other: BitByteList): BitByteList = this.zip(other) { a, b -> a xor b }

  fun not(): BitByteList = BitByteList(this.toList().map { it.not() })

  fun rotateRight(bitCount: Int): BitByteList {
    val normCount = when {
      bitCount >= 0 -> bitCount % bitN
      else -> (bitCount % bitN) + bitN
    }
    val fullBytes = normCount.div(8)
    val leftoverBits = normCount % 8
    val rotatedByBytes = this.rotateRightByBytes(fullBytes)
    val rotatedByOneMoreByte = rotatedByBytes.rotateRightByBytes(1)
    return rotatedByBytes.zip(rotatedByOneMoreByte) { bb, fill -> bb.shiftRight(leftoverBits, fill) }
  }

  fun rotateRightByBytes(byteCount: Int): BitByteList {
    val normCount = when {
      byteCount >= 0 -> byteCount % byteN
      else -> (byteCount % byteN) + byteN
    }
    return this.toList().let {
      val right = it.takeLast(normCount)
      val left = it.dropLast(normCount)
      BitByteList(right + left)
    }
  }

  fun rotateLeft(bitCount: Int): BitByteList =
    rotateRight(-bitCount)

  fun rotateLeftByBytes(byteCount: Int): BitByteList =
    rotateRightByBytes(-byteCount)

  fun bitSum(): Int =
    this.toList().sumOf { it.bitSum() }


  fun toList(): List<BitByte> = bitBytes

  fun toByteArray(): ByteArray = toList().map { it.toByte() }.toByteArray()

  fun toBinString(): String = bitBytes.joinToString(separator = "") { it.toBinString() }

  fun toHexString(): String = bitBytes.joinToString(separator = "") { it.toHexString() }

  fun toText(): String = toByteArray().toString(Consts.CHARSET)


  override fun toString(): String = "BitByteList(${toHexString()})"


  companion object {
    fun from(byteArray: ByteArray): BitByteList =
      BitByteList(byteArray.map { BitByte(it.toUByte()) })
  }
}