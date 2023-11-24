package rsa

import agno.BitByteList
import java.math.BigInteger

class RsaBlock private constructor(val block: BitByteList) {
  init {
    assert(block.byteN == BLOCK_LEN) {
      "RSA block needs to be $BLOCK_LEN bytes long (tried to assign ${block.byteN} bytes instead)"
    }
  }

  fun toBigInteger(): BigInteger = block.toBigInteger()

  fun applyToBigInteger(operation: (BigInteger) -> BigInteger): RsaBlock =
    fromBigInteger(operation(toBigInteger()))


  companion object {
    fun fromBigInteger(bigInteger: BigInteger): RsaBlock =
      RsaBlock(BitByteList.from(bigInteger, BLOCK_LEN))

    fun listFromBitByteList(bitByteList: BitByteList): List<RsaBlock> {
      val padded = bitByteList.pad(BLOCK_LEN)
      val chunks = padded.chunked(BLOCK_LEN)
      return chunks.map { RsaBlock(it) }
    }

    fun toBitByteList(rsaBlocks: List<RsaBlock>): BitByteList =
      rsaBlocks
        .map { it.block }
        .let { BitByteList.fromMultiple(it) }
        .depad()
  }
}

private const val BLOCK_LEN = 10