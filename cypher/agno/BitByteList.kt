package agno

import java.math.BigInteger

@Suppress("MemberVisibilityCanBePrivate", "unused")
class BitByteList(private val bitBytes: List<BitByte>) {
  constructor(vararg bitBytes: BitByte) : this(bitBytes.asList())

  val byteN = bitBytes.size
  val bitN = byteN * 8


  operator fun plus(other: BitByteList): BitByteList =
    BitByteList(bitBytes + other.toList())

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

  fun toBigInteger(): BigInteger {
    var ret = BigInteger.ZERO
    bitBytes.forEach {
      ret = ret.shiftLeft(8)
      ret += it.uByte.toInt().toBigInteger()
    }
    return ret
  }


  /** Pad so that byte length is divisible by lenDiv. Pad is a single 0xFF, and then zero or more 0x00s */
  fun pad(lenDiv: Int): BitByteList {
    val lenWith0xFF = byteN + 1
    val required0s =
      if (lenWith0xFF % lenDiv != 0) {
        lenWith0xFF - (lenWith0xFF % lenDiv)
      } else 0
    val pad = mutableListOf(BitByte.FULL)
    repeat(required0s) { pad.add(BitByte.ZERO) }
    return BitByteList(this.bitBytes + pad)
  }

  /** Removes 0xFF 0x00 0x00... padding. Should not be used on a non-padded BitByteList */
  fun depad(): BitByteList =
    BitByteList(bitBytes.dropLastWhile { it == BitByte.ZERO }.dropLast(1))

  fun subList(fromIndex: Int, toIndex: Int): BitByteList =
    BitByteList(bitBytes.subList(fromIndex, toIndex))

  fun chunked(size: Int): List<BitByteList> =
    bitBytes.chunked(size).map { BitByteList(it) }


  override fun toString(): String = "BitByteList(${toHexString()})"


  companion object {
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
  }
}