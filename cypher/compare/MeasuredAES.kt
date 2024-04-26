package compare

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class MeasuredAES(private val keySize: AESize) : MeasuredCypher<MeasuredAES.AESKey>() {
  override val name: String = "AES${keySize.bits}"

  private val keyGenerator =
    KeyGenerator.getInstance("AES").also { it.init(keySize.bits) }
  private val randGen = SecureRandom.getInstanceStrong()
  private val cipherInstance: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

  override fun doGenerateKey(): AESKey = AESKey(
    keyGenerator.generateKey(),
    ByteArray(16)
      .also { randGen.nextBytes(it) }
      .let { IvParameterSpec(it) },
  )

  override fun doEncode(plainText: ByteArray): ByteArray {
    cipherInstance.init(Cipher.ENCRYPT_MODE, getKey().key, getKey().ivSpec)
    return cipherInstance.doFinal(plainText)
  }

  override fun doDecode(cypherText: ByteArray): ByteArray {
    cipherInstance.init(Cipher.DECRYPT_MODE, getKey().key, getKey().ivSpec)
    return cipherInstance.doFinal(cypherText)  }

  enum class AESize(val bits: Int) {
    AES128(128),
    AES192(192),
    AES256(256),
  }

  data class AESKey (
    val key: SecretKey,
    val ivSpec: IvParameterSpec,
  )
}
