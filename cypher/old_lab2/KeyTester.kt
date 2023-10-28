import kotlin.math.sqrt
import org.apache.commons.math3.special.Erf

object KeyTester {
  /** @return `true` if sequence is said to be random */
  fun monobitTest(generator: (Int) -> List<BitByte>, byteLen: Int): Boolean =
    monobitTest(generator(byteLen))

  fun monobitTest(key: List<BitByte>): Boolean {
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
    val sN = key.fold(0) { acc, bitByte ->
      acc + (2 * bitByte.bitSum() - 8)
    }
    val sObs = sN / sqrt(key.size * 8.0)
    val pVal = Erf.erfc(sObs / sqrt(2.0))
    return pVal >= 0.01
  }
}
