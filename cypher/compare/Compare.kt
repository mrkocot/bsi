package compare

import javax.crypto.IllegalBlockSizeException
import kotlin.random.Random

object Compare {
  @JvmStatic
  fun main(args: Array<String>) {
    println("Algorithm ,Test      ,Size      ,Nanoseconds")
    allAlgorithms.forEach { it.measureAllAndPrintCSV() }
  }

  private fun MeasuredCypher<*>.measureAllAndPrintCSV() {
    val encoDeco = avgOfNED(10) { this.measureEncryptions() }
    val genResult = avgOfN(10) { this.testGenerations() }
//    val encoDeco = this.measureEncryptions()
//    val genResult = this.testGenerations()
    val encoResult = encoDeco.enco
    val decoResult = encoDeco.deco

    printCSVRows(this.name, "keygen", genResult)
    printCSVRows(this.name, "encoding", encoResult)
    printCSVRows(this.name, "decoding", decoResult)
  }

  private fun MeasuredCypher<*>.testGenerations(): Map<Int, Long> {
    val result = mutableMapOf<Int, Long>()
//    var n = 1
    var n = 1
    while (n <= MAX_KEY_GENS) {
      result[n] = this.measureNGenerations(n)
      n *= 10
    }
    return result.toMap()
  }

  private fun MeasuredCypher<*>.measureEncryptions(): EncoDeco<Map<Int, Long>> {
    this.generateKey()
    val resultEnco = mutableMapOf<Int, Long>()
    val resultDeco = mutableMapOf<Int, Long>()
    val rGen = Random(1234)
    var n = 1
    while (n <= MAX_TEXT_BYTES) {
      val text = rGen.nextBytes(n)
      try {
        val encoded = this.encode(text)
        val decoded = this.decode(encoded.value)
        resultEnco[n] = encoded.nanos
        resultDeco[n] = decoded.nanos
      } catch (e: IllegalBlockSizeException) {
        break
      }
      n *= 10
    }
    return EncoDeco(resultEnco.toMap(), resultDeco.toMap())
  }

  private fun printCSVRows(algo: String, test: String, results: Map<Int, Long>) {
    results.forEach { printCSVRow(algo, test, it.key, it.value) }
  }

  private fun printCSVRow(
    algo: String,
    test: String,
    size: Int,
    millis: Long,
  ) {
    println("${algo.toWidth(10)},${test.toWidth(10)},${size.toString().toWidth(10)},${millis}")
  }
}

private val allAlgorithms = listOf<MeasuredCypher<*>>(
//  Measured3DES(),
//  MeasuredAES(MeasuredAES.AESize.AES128),
//  MeasuredAES(MeasuredAES.AESize.AES192),
//  MeasuredAES(MeasuredAES.AESize.AES256),
  MeasuredRSA(512),
  MeasuredRSA(1024),
  MeasuredRSA(2048),
//  MeasuredRSA(4096),
)

private const val MAX_KEY_GENS = 1000
//private const val MAX_KEY_GENS = 100

private const val MAX_TEXT_BYTES = 1000000
//private const val MAX_TEXT_BYTES = 100

private fun String.toWidth(width: Int): String =
  if (this.length >= width) this
  else this + " ".repeat(width - this.length)

private fun avgOfN(n: Int, test: (Int) -> Map<Int, Long>): Map<Int, Long> =
  (0 until n)
    .flatMap { test(it).entries }
    .groupBy { it.key }
    .mapValues { it.value.sumOf { x -> x.value } / it.value.size }

private fun avgOfNED(n: Int, test: () -> EncoDeco<Map<Int, Long>>): EncoDeco<Map<Int, Long>> {
  val results = (0 until n).map { test() }
  return EncoDeco(
    avgOfN(n) { results[it].enco },
    avgOfN(n) { results[it].deco },
  )
}

private data class EncoDeco<T>(
  val enco: T,
  val deco: T,
)
