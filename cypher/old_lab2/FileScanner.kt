import java.io.FileReader

object FileScanner {
  fun fileToBitBytes(path: String): List<BitByte> =
    BitByte.from(fileToBytes(path))

  private fun fileToBytes(path: String): ByteArray =
    fileToText(path).toByteArray(Consts.CHARSET)

  fun fileToText(path: String): String {
    val reader = FileReader(path, Consts.CHARSET)
    return reader.readText()
  }
}
