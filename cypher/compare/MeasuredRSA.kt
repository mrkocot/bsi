package compare

import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.Cipher

class MeasuredRSA(keySize: Int) : MeasuredCypher<KeyPair>() {
  override val name: String = "RSA$keySize"

  private val generator: KeyPairGenerator =
    KeyPairGenerator.getInstance("RSA").also { it.initialize(keySize) }
  private val cipherInstance = Cipher.getInstance("RSA")

  override fun doGenerateKey(): KeyPair =
    this.generator.genKeyPair()

  override fun doEncode(plainText: ByteArray): ByteArray {
    cipherInstance.init(Cipher.ENCRYPT_MODE, getKey().public)
    return cipherInstance.doFinal(plainText)
  }

  override fun doDecode(cypherText: ByteArray): ByteArray {
    cipherInstance.init(Cipher.DECRYPT_MODE, getKey().private)
    return cipherInstance.doFinal(cypherText)
  }
}