package com.example.cryptography_app

import android.security.keystore.KeyProperties
import com.example.cryptography_app.MainActivity.Companion.AES
import com.example.cryptography_app.MainActivity.Companion.AES_TRANSFORMATION
import com.example.cryptography_app.MainActivity.Companion.KEY_SIZE
import com.example.cryptography_app.MainActivity.Companion.MY_SECRET_KEY
import com.example.cryptography_app.MainActivity.Companion.RSA_TRANSFORMATION
import com.example.cryptography_app.MainActivity.Companion.SHA_256
import com.example.cryptography_app.MainActivity.Companion.SIGN_ALGORITHM_SHA1_RSA
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
//Symmetric
fun generateAESKey(): SecretKeySpec {
    val digest: MessageDigest = MessageDigest.getInstance(SHA_256)
    val bytes = MY_SECRET_KEY.toByteArray()
    digest.update(bytes, 0, bytes.size)
    val key = digest.digest()
    return SecretKeySpec(key, AES)
}

fun encryptAES(strToEncrypt: String, secretKey: SecretKeySpec): Encrypt {
    val plainText = strToEncrypt.toByteArray(Charsets.UTF_8)
    val cipher = Cipher.getInstance(AES_TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val cipherText = cipher.doFinal(plainText)
    return Encrypt(strToEncrypt, cipherText, cipher.iv)
}

fun decryptAES(encryptedString: ByteArray, secretKey: SecretKeySpec, ivValue: ByteArray): String {
    val cipher = Cipher.getInstance(AES_TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(ivValue))
    val cipherText = cipher.doFinal(encryptedString)
    return cipherText.decodeToString()
}

//Asymmetric
fun generateRSAKey(): RSAKeys {
    val keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
    keyGen.initialize(KEY_SIZE)
    val pair = keyGen.generateKeyPair()
    return RSAKeys(pair.private, pair.public)
}

fun encryptRSA(strToEncrypt: String, publicKey: PublicKey?): RSA {
    val plainText = strToEncrypt.toByteArray(Charsets.UTF_8)
    val digestNumber = generateMsgDigest(plainText)
    val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    val encryptedString = cipher.doFinal(plainText)
    return RSA(encryptedString, digestNumber)

}

fun decryptRSA(encryptedString: ByteArray?, privateKey: PrivateKey?): String {
    val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    val cipherText = cipher.doFinal(encryptedString)
    return cipherText.decodeToString()
}

//Digital sign
fun generateMsgDigest(txtFile: ByteArray): ByteArray {
    val message: ByteArray = txtFile
    val md = MessageDigest.getInstance(SHA_256)
    return md.digest(message)
}

fun generateDigitalSign(strToEncrypt: String, privateKey: PrivateKey): ByteArray? {
    val message: ByteArray = strToEncrypt.encodeToByteArray()
    val key: PrivateKey = privateKey
    val signature = Signature.getInstance(SIGN_ALGORITHM_SHA1_RSA)
        .apply {
            initSign(key)
            update(message)
        }
    return signature.sign()
}

fun verifyDigitalSign(txtFile: String, fileSignature: ByteArray?, publicKey: PublicKey): Boolean {
    val message: ByteArray = txtFile.encodeToByteArray()
    val signature: ByteArray? = fileSignature
    val key: PublicKey = publicKey
    val s = Signature.getInstance(SIGN_ALGORITHM_SHA1_RSA)
        .apply {
            initVerify(key)
            update(message)
        }
    return s.verify(signature)
}
