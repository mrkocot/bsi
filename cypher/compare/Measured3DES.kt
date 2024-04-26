package compare

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class Measured3DES : MeasuredCypher<Measured3DES.TripleDESKey>() {
  override val name: String = "3DES"

  private val cipherInstance: Cipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding")
  private val randGen = SecureRandom.getInstanceStrong()

  override fun doGenerateKey(): TripleDESKey {
    val keyBytes = ByteArray(24)
    randGen.nextBytes(keyBytes)
    val ivBytes = ByteArray(8)
    randGen.nextBytes(ivBytes)
    return TripleDESKey(
      SecretKeySpec(keyBytes, "TripleDES"),
      IvParameterSpec(ivBytes),
    )
  }

  override fun doEncode(plainText: ByteArray): ByteArray {
    cipherInstance.init(Cipher.ENCRYPT_MODE, getKey().keySpec, getKey().ivSpec)
    return cipherInstance.doFinal(plainText)
  }

  override fun doDecode(cypherText: ByteArray): ByteArray {
    cipherInstance.init(Cipher.DECRYPT_MODE, getKey().keySpec, getKey().ivSpec)
    return cipherInstance.doFinal(cypherText)
  }

  data class TripleDESKey (
    val keySpec: SecretKeySpec,
    val ivSpec: IvParameterSpec,
  )
}
