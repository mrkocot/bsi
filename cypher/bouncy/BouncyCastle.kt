package bouncy

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class BouncyCastle {
  private val charset = Charsets.UTF_8
  private val tempDir: Path
  private val rand = SecureRandom()

  init {
    Security.addProvider(BouncyCastleProvider())
    tempDir = Files.createTempDirectory("bouncycastle")
    println("Generated raccoons directory: ${tempDir.toUri()}")
  }

  fun perform3DES(files: Pair<String, String>, key: String, shouldDecrypt: Boolean, iv: ByteArray? = null): ByteArray =
    performSymmetric(files, key, "DESede", "DESede/CBC/PKCS7Padding", shouldDecrypt, iv)

  fun performBlowfish(files: Pair<String, String>, key: String, shouldDecrypt: Boolean, iv: ByteArray? = null): ByteArray =
    performSymmetric(files, key, "Blowfish", "Blowfish/CBC/PKCS5Padding", shouldDecrypt, iv)

  private fun performSymmetric(
    files: Pair<String, String>,
    key: String,
    algo: String,
    transformation: String,
    shouldDecrypt: Boolean,
    iv: ByteArray?,
  ): ByteArray {
    val beforeData = readFrom(files.first)
    val secretKeySpec = SecretKeySpec(key.toByteArray(Charsets.US_ASCII), algo)
    val cipher = getCipher(
      secretKeySpec,
      transformation,
      shouldDecrypt,
      iv?.let { OptionalIvWrapper.IHaveIt(it) } ?: OptionalIvWrapper.PleaseGenerate,
    )
    cipher.doFinal(beforeData).writeToBouncy(files.second)
    return cipher.iv
  }

  fun asymmetricEncrypt(plain: String, publicKey: PublicKey, algo: Asymmetric): ByteArray =
    performAsymmetric(
      plain.toByteArray(charset),
      OneKey.Public(publicKey),
      if (algo == Asymmetric.RSA) "RSA/None/OAEPWithSHA1AndMGF1Padding" else "ECIES"
    )

  fun asymmetricDecrypt(crypt: ByteArray, privateKey: PrivateKey, algo: Asymmetric): String =
    performAsymmetric(
      crypt,
      OneKey.Private(privateKey),
      if (algo == Asymmetric.RSA) "RSA/None/OAEPWithSHA1AndMGF1Padding" else "ECIES"
    ).toString(charset)

  private fun performAsymmetric(
    data: ByteArray,
    key: OneKey,
    transformation: String,
  ): ByteArray {
    val cipher = when (key) {
      is OneKey.Private -> getCipher(key.key, transformation, true)
      is OneKey.Public -> getCipher(key.key, transformation, false)
    }
    return cipher.doFinal(data)
  }

  fun generateKeyPair(algo: Asymmetric): KeyPair {
    val generator = when (algo) {
      Asymmetric.RSA -> KeyPairGenerator.getInstance("RSA", "BC")
        .also { it.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)) }
      Asymmetric.EC -> KeyPairGenerator.getInstance("EC", "BC")
        .also { it.initialize(ECGenParameterSpec("prime256v1")) }
    }
    return generator.generateKeyPair()
  }

  fun performMD5(file: String): String = performHash(file, false)

  fun performSHA512(file: String): String = performHash(file, true)

  private fun performHash(file: String, useSHA512InsteadOfMD5: Boolean): String {
    val data = readFrom(file)
    val algo = if (useSHA512InsteadOfMD5) "SHA-512" else "MD5"
    return MessageDigest.getInstance(algo).digest(data).joinToString("") { "%02x".format(it) }
  }

  fun performSignature(file: String, key: PrivateKey): ByteArray {
    val data = readFrom(file)
    val signature: Signature = Signature.getInstance("SHA512withECDSA")
    signature.initSign(key)
    signature.update(data)
    return signature.sign()
  }

  fun verifySignature(file: String, signature: ByteArray, key: PublicKey): Boolean {
    val data = readFrom(file)
    val signInstance: Signature = Signature.getInstance("SHA512withECDSA")
    signInstance.initVerify(key)
    signInstance.update(data)
    return signInstance.verify(signature)
  }

  // // // //

  private fun getCipher(
    key: Key,
    transformation: String,
    shouldDecrypt: Boolean,
    iv: OptionalIvWrapper = OptionalIvWrapper.NotNeeded,
  ): Cipher {
    val cipher = Cipher.getInstance(transformation, "BC")
    val mode = if (shouldDecrypt) Cipher.DECRYPT_MODE else Cipher.ENCRYPT_MODE
    val ivSpec: IvParameterSpec? = when (iv) {
      is OptionalIvWrapper.IHaveIt -> IvParameterSpec(iv.iv)
      OptionalIvWrapper.PleaseGenerate -> ByteArray(cipher.blockSize).let { rand.nextBytes(it); IvParameterSpec(it) }
      OptionalIvWrapper.NotNeeded -> null
    }
    if (ivSpec != null) {
      cipher.init(mode, key, ivSpec)
    } else {
      cipher.init(mode, key)
    }
    return cipher
  }

  private fun readFrom(filePath: String): ByteArray {
    val path = filePath.asBouncyCastlePath()
    return Files.readAllBytes(path)
  }

  private fun ByteArray.writeToBouncy(filePath: String) {
    val path = filePath.asBouncyCastlePath()
    if (!Files.exists(path)) Files.createFile(path)
    Files.write(path, this)
  }

  private fun String.asBouncyCastlePath(): Path =
    if (this.startsWith("[TEMP]")) tempDir.resolve(this.drop(6)) else Paths.get(this)

  // // // //

  private sealed class OptionalIvWrapper {
    object PleaseGenerate : OptionalIvWrapper()
    object NotNeeded : OptionalIvWrapper()
    class IHaveIt(val iv: ByteArray) : OptionalIvWrapper()
  }

  sealed class OneKey {
    class Private(val key: PrivateKey) : OneKey()
    class Public(val key: PublicKey) : OneKey()
  }

  enum class Asymmetric {
    RSA,
    EC
  }
}
