package agno

import java.io.FileReader

@Suppress("MemberVisibilityCanBePrivate")
object FileScanner {
  fun fileToBitBytes(path: String): BitByteList =
    BitByteList.from(fileToBytes(path))

  private fun fileToBytes(path: String): ByteArray =
    fileToText(path).toByteArray(Consts.CHARSET)

  fun fileToText(path: String): String {
    val reader = FileReader(path, Consts.CHARSET)
    return reader.readText()
  }
}
