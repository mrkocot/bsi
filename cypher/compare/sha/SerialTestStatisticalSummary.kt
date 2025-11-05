package compare.sha

import agno.BitByteList
import org.apache.commons.math3.stat.descriptive.StatisticalSummary
import kotlin.math.sqrt

class SerialTestStatisticalSummary(hash: BitByteList) : StatisticalSummary {
  val muR: Double
  val theR: Double
  val sd: Double

  init {
    val bitN = hash.bitN
    val n1 = hash.bitSum()
    val n0 = bitN - n1
    var varR = 2  // the first and the last bit automatically do count
//    if (hash.getBit(0) != hash.getBit(1)) R++
//    if (hash.getBit(bitN - 2) != hash.getBit(bitN - 1)) R++
    for (i in 1..(bitN - 2)) {
      if (hash.getBit(i-1) != hash.getBit(i+1)) varR++
    }

    // Long, because otherwise SHA-512 might overflow
    val variance = (2L * n0 * n1 * (2 * n0 * n1 - n0 - n1)) / ((n0 + n1) * (n0 + n1) * (n0 + n1 - 1))

    theR = varR.toDouble()
    muR = 1.0 + (2 * n0 * n1) / (n0 + n1)
    sd = sqrt(variance.toDouble())
  }

  override fun getMean(): Double = theR

  override fun getVariance(): Double = sd * sd

  override fun getStandardDeviation(): Double = sd

  override fun getMax(): Double = theR

  override fun getMin(): Double = theR

  override fun getN(): Long = 1L

  override fun getSum(): Double = theR
}