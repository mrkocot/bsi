package agno

import java.math.BigInteger

@Suppress("MemberVisibilityCanBePrivate", "unused")
class BitByteList(private val bitBytes: List<BitByte>) {
  constructor(vararg bitBytes: BitByte) : this(bitBytes.asList())

  val byteN = bitBytes.size
  val bitN = byteN * 8


  operator fun plus(other: BitByteList): BitByteList =
    BitByteList(bitBytes + other.toList())

  operator fun plus(bitByte: BitByte): BitByteList =
    BitByteList(bitBytes + bitByte)

  operator fun get(index: Int): BitByte =
    bitBytes[index]


  fun zip(other: BitByteList, function: (BitByte, BitByte) -> BitByte): BitByteList =
    if (this.byteN == other.byteN) {
      this.toList()
        .zip(other.toList()) { a, b -> function(a, b) }
        .let { BitByteList(it) }
    } else {
      error("Trying to zip BitByteLists with different sizes (${this.byteN} vs ${other.byteN})")
    }

  fun take(n: Int): BitByteList = BitByteList(bitBytes.take(n))
  fun takeLast(n: Int): BitByteList = BitByteList(bitBytes.takeLast(n))
  fun drop(n: Int): BitByteList = BitByteList(bitBytes.drop(n))
  fun dropLast(n: Int): BitByteList = BitByteList(bitBytes.dropLast(n))

  /** Similar to `takeLast`, but the result will always have exactly n bytes */
  fun takeLastExactly(n: Int): BitByteList = takeLast(n).addLeadingZerosToLen(n)


  infix fun numberAdd(other: BitByteList): BitByteList =
    from(this.toBigInteger() + other.toBigInteger())

  infix fun and(other: BitByteList): BitByteList = this.zip(other) { a, b -> a and b }

  infix fun or(other: BitByteList): BitByteList = this.zip(other) { a, b -> a or b }

  infix fun xor(other: BitByteList): BitByteList = this.zip(other) { a, b -> a xor b }

  fun not(): BitByteList = BitByteList(this.toList().map { it.not() })

  fun rightMask(bits: Int): BitByteList {
    return if (bits >= bitN) {
      fromRepeated(BitByte.FULL, byteN)
    } else {
      val full = bits.div(8)
      val remainder = bits % 8
      val borderBitByte = BitByte.FULL shiftRight (8 - remainder)
      (BitByteList(borderBitByte) + fromRepeated(BitByte.FULL, full)).addLeadingZerosToLen(byteN)
    }
  }

  fun leftMask(bits: Int): BitByteList = rightMask(bits).reverse()


  fun shiftRight(bitCount: Int): BitByteList {
    val bitsSaved = bitN - bitCount
    return when {
      (bitsSaved > 0) -> rotateRight(bitCount) and rightMask(bitsSaved)
      else -> fromRepeated(BitByte.FULL, byteN)
    }
  }

  fun rotateRight(bitCount: Int): BitByteList {
    if (bitCount % 8 == 0) return rotateRightByBytes(bitCount.div(8))

    val normCount = when {
      bitCount >= 0 -> bitCount % bitN
      else -> (bitCount % bitN) + bitN
    }
    val fullBytes = normCount.div(8)
    val leftoverBits = normCount % 8
    val rotatedByBytes = this.rotateRightByBytes(fullBytes)
    val direction = if (bitCount >= 0) 1 else -1
    val rotatedByOneMoreByte = rotatedByBytes.rotateRightByBytes(direction)
    return rotatedByBytes.zip(rotatedByOneMoreByte) { bb, fill -> bb.shiftRight(leftoverBits, fill) }
  }

  fun rotateRightByBytes(byteCount: Int): BitByteList {
    if (byteCount == 0) return this

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

  fun shiftLeft(bitCount: Int): BitByteList {
    val bitsSaved = bitN - bitCount
    return when {
      (bitsSaved > 0) -> rotateLeft(bitCount) and leftMask(bitsSaved)
      else -> fromRepeated(BitByte.FULL, byteN)
    }
  }

  fun rotateLeft(bitCount: Int): BitByteList =
    rotateRight(-bitCount)

  fun rotateLeftByBytes(byteCount: Int): BitByteList =
    rotateRightByBytes(-byteCount)


  fun reverse(): BitByteList =
    bitBytes
      .map { it.reverse() }
      .reversed()
      .let { BitByteList(it) }


  fun bitSum(): Int =
    this.toList().sumOf { it.bitSum() }


  fun toList(): List<BitByte> = bitBytes

  fun toByteArray(): ByteArray = toList().map { it.toByte() }.toByteArray()

  fun toBinString(): String = bitBytes.joinToString(separator = "") { it.toBinString() }

  fun toHexString(): String = bitBytes.joinToString(separator = "") { it.toHexString() }

  fun toText(): String = toByteArray().toString(Consts.CHARSET)

  fun toBigInteger(): BigInteger {
    var ret = BigInteger.ZERO
    bitBytes.forEach {
      ret = ret.shiftLeft(8)
      ret += it.uByte.toInt().toBigInteger()
    }
    return ret
  }

  fun toInt(): Int = toBigInteger().toInt()

  fun toLong(): Long = toBigInteger().toLong()


  /** Pad so that byte length divided by lenDiv gives remainder lenMod. Pad is a single 0xFF, and then zero or more 0x00s */
  fun pad(lenDiv: Int, lenMod: Int = 0, padByte: BitByte = BitByte.FULL): BitByteList {
    if (lenMod >= lenDiv) error("MOD can't be larger than divisor")
    val lenWith0xFF = byteN + 1
    val required0s = when {
      lenWith0xFF % lenDiv < lenMod -> lenMod - lenWith0xFF % lenDiv
      lenWith0xFF % lenDiv > lenMod -> lenDiv + lenMod - lenWith0xFF % lenDiv
      else -> 0
    }
    val pad = mutableListOf(padByte)
    repeat(required0s) { pad.add(BitByte.ZERO) }
    return BitByteList(this.bitBytes + pad)
  }

  /** Removes 0xFF 0x00 0x00... padding. Should not be used on a non-padded BitByteList */
  fun depad(): BitByteList =
    BitByteList(bitBytes.dropLastWhile { it == BitByte.ZERO }.dropLast(1))

  fun addLeadingZerosToLen(byteLen: Int): BitByteList =
    when {
      byteN < byteLen -> fromRepeated(BitByte.ZERO, byteLen - byteN) + this
      else -> this
    }

  fun subList(fromIndex: Int, toIndex: Int): BitByteList =
    BitByteList(bitBytes.subList(fromIndex, toIndex))

  fun chunked(size: Int): List<BitByteList> =
    bitBytes.chunked(size).map { BitByteList(it) }


  override fun toString(): String = "BitByteList(${toHexString()})"


  companion object {
    val EMPTY: BitByteList = BitByteList(emptyList())

    fun from(text: String): BitByteList = from(text.toByteArray(Consts.CHARSET))

    fun from(byteArray: ByteArray): BitByteList =
      BitByteList(byteArray.map { BitByte(it.toUByte()) })

    fun from(bigInteger: BigInteger): BitByteList = from(bigInteger.toByteArray())

    fun from(bigInteger: BigInteger, expectedLen: Int): BitByteList {
      var bytes = bigInteger.toByteArray().dropWhile { it.compareTo(0) == 0 }.toByteArray()
      if (bytes.size > expectedLen) {
        error("Tried to make $expectedLen bytes from a BigInteger too large")
      } else {
        while (bytes.size < expectedLen) bytes = byteArrayOf(0) + bytes
      }
      return from(bytes)
    }

    fun fromMultiple(others: List<BitByteList>): BitByteList =
      others.fold(BitByteList(emptyList())) { acc, next -> acc + next }

    fun fromRepeated(bitByte: BitByte, number: Int): BitByteList {
      val filled = Array(number) { bitByte }
      return BitByteList(filled.toList())
    }

    fun numberSum(bitByteLists: List<BitByteList>): BitByteList =
      bitByteLists
        .map { it.toBigInteger() }
        .sumOf { it }
        .let { from(it) }

    fun numberSum(vararg bitByteLists: BitByteList): BitByteList =
      numberSum(bitByteLists.toList())
  }
}