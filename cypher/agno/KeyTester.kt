package agno

import kotlin.math.sqrt
import org.apache.commons.math3.special.Erf

@Suppress("MemberVisibilityCanBePrivate")
object KeyTester {
  /** @return `true` if sequence is said to be random */
  fun monobitTest(generator: (Int) -> BitByteList, byteLen: Int): Boolean =
    monobitTest(generator(byteLen))

  fun monobitTest(key: BitByteList): Boolean {
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
    val sN = key.toList().fold(0) { acc, bitByte ->
      acc + (2 * bitByte.bitSum() - 8)
    }
    val sObs = sN / sqrt(key.bitN.toDouble())
    val pVal = Erf.erfc(sObs / sqrt(2.0))
    return pVal >= 0.01
  }
}
