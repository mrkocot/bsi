package sha

import agno.BitByte
import agno.BitByteList

object SHA256 {
  private val H = listOf<Long>(
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ).map { it.toBitByteList() }

  private val K = listOf(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ).map { it.toBitByteList() }

  private fun Long.toBitByteList() = BitByteList.from(this.toBigInteger(), 4)

  fun digest(message: BitByteList) =
    prepareShaBlocks(message).map(::cutIntoWords).digestBlocks()

  private fun prepareShaBlocks(message: BitByteList): List<BitByteList> {
    val paddedMessage = message.pad(64, 56, padByte = BitByte.MSB)
    val messageLen = message.bitN.toBigInteger()
    val fullMessage = paddedMessage + BitByteList.from(messageLen, 8)
    return fullMessage.chunked(64)
  }

  private fun cutIntoWords(block: BitByteList): Words64 {
    if (block.bitN != 512) error("In SHA-256, block should have exactly 512 bits (has ${block.bitN})")
    return Words16(block.chunked(4)).expand()
  }

  private fun List<Words64>.digestBlocks(): BitByteList =
    this.fold(initHash()) { hash, block -> hash.digestBlock(block) }.squish()

  private fun initHash(): Hash = Hash(H)


  open class Words(expectedWordN: Int, words: List<BitByteList>) {
    val words = words.map { it.takeLastExactly(4) }

    init {
      if (words.size != expectedWordN) error("Block has to have exactly $expectedWordN words (has ${words.size})")
    }

    operator fun get(index: Int): BitByteList = words[index]

    fun squish(): BitByteList = BitByteList.fromMultiple(words)
  }

  class Words16(words: List<BitByteList>) : Words(16, words) {
    fun expand(): Words64 {
      val w = this.words.toMutableList()
      for (i in 16..63) {
        val s0 =
          w[i-15].rotateRight(7) xor
            w[i-15].rotateRight(18) xor
            w[i-15].shiftRight(3)
        val s1 =
          w[i-2].rotateRight(17) xor
            w[i-2].rotateRight(19) xor
            w[i-2].shiftRight(10)
        w.add(BitByteList.numberSum(w[i-16], s0, w[i-7], s1).takeLastExactly(4))
      }
      return Words64(w.toList())
    }
  }

  class Words64(words: List<BitByteList>) : Words(64, words)

  class Hash(abcdefgh: List<BitByteList>) : Words(8, abcdefgh) {
    constructor(vararg abcdefgh: BitByteList) : this(abcdefgh.toList())

    private val a = this[0]
    private val b = this[1]
    private val c = this[2]
    private val d = this[3]
    private val e = this[4]
    private val f = this[5]
    private val g = this[6]
    private val h = this[7]

    fun digestBlock(w: Words64): Hash {
      var result = this
      repeat(64) { result = result.step(it, w) }
      return finalise(result)
    }

    private fun step(i: Int, w: Words64): Hash {
      val s1 = e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)
      val ch = (e and f) xor (e.not() and g)
      val t1 = BitByteList.numberSum(h, s1, ch, K[i], w[i])
      val s0 = a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)
      val maj = (a and b) xor (a and c) xor (b and c)
      val t2 = s0 numberAdd maj

      return Hash(
        t1 numberAdd t2,
        a,
        b,
        c,
        d numberAdd t1,
        e,
        f,
        g,
      )
    }

    private fun finalise(result: Hash): Hash =
      Hash((0..7).map { this[it] numberAdd result[it] })
  }
}