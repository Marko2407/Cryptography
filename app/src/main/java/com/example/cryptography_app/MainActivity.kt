package com.example.cryptography_app

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.example.cryptography_app.databinding.ActivityMainBinding
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Objects
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    private var text = ""
    private var textFilePath = ""

    //AES i RSA podatci
    private var aesKey: SecretKeySpec? = null
    private var aesData: Encrypt? = null
    private var rsaPrivateKey: PrivateKey? = null
    private var rsaPublicKey: PublicKey? = null
    private var rsaData: RSA? = null
    private var digitalSign: ByteArray? = null


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setOnClickListeners()
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        //Load inital tekst
        if (requestCode == 111 && resultCode == RESULT_OK) {
            text = readTextFromUri(data?.data)
            textFilePath = data?.data?.path.toString()
            binding.txtFileName.text = textFilePath
            binding.txtFileContent.text = getString(R.string.file_content, text)
            aesKey = null
            aesData = null
            logData()
        }
        //AES decrypt
        if (requestCode == 112 && resultCode == RESULT_OK) {
            val encryptedText = readTextUri(data?.data)
            if (encryptedText != null) {
                decryptDataAES(encryptedText)
            }
        }
        //RSA decrypt
        if (requestCode == 113 && resultCode == RESULT_OK) {
            val encryptedText = readTextUri(data?.data)
            if (encryptedText != null) {
                decryptDataRSA(encryptedText)
            }
        }
        if (requestCode == 114 && resultCode == RESULT_OK) {
            val digitalSignature = readTextUri(data?.data)
            if (digitalSignature != null) {
                signatureVerify(digitalSignature)
            }
        }

    }

    private fun setOnClickListeners() {
        binding.txtFileName.setOnClickListener {
            openDataSelector(111)
        }

        //key creators listeners
        binding.btnKeyAESCreator.setOnClickListener {
            generateAES()
        }
        binding.btnKeyRSACreator.setOnClickListener {
            generateRSA()
        }

        //encrypt and decrypt listeners
        binding.btnKeyAESEncrypt.setOnClickListener {
            encryptDataAES()
        }
        binding.btnKeyAESDecrypt.setOnClickListener {
            openDataSelector(112)
        }

        binding.btnKeyRSAEncrypt.setOnClickListener {
            encryptDataRSA()
        }
        binding.btnKeyRSADecrypt.setOnClickListener {
            openDataSelector(113)
        }

        //digital sign
        binding.btnCalculate.setOnClickListener {
            setDigestNumber()
        }
        binding.btnDigitalSign.setOnClickListener {
            digitalSigning()
        }
        binding.btnKeySignVerification.setOnClickListener {
            openDataSelector(114)
        }
    }

    private fun readTextFromUri(uri: Uri?): String {
        val stringBuilder = StringBuilder()
        if (uri != null) {
            this.contentResolver.openInputStream(uri).use { inputStream ->
                BufferedReader(
                    InputStreamReader(Objects.requireNonNull(inputStream))
                ).use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        stringBuilder.append(line)
                    }
                }
            }
        }
        return stringBuilder.toString()
    }


    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun readTextUri(uri: Uri?): ByteArray? {
        var bytes: ByteArray? = null
        if (uri != null) {
            this.contentResolver.openInputStream(uri).use {
                bytes = it?.readAllBytes()
            }
        }
        return bytes
    }

    private fun encryptDataAES() {
        if (isAESDataValid()) {
            aesData = encryptAES(text, aesKey!!)
            msgLog(ENCRYPTED_AES_TEXT + aesData!!.cipherText)
            binding.txtEncryptedText.text =
                getString(R.string.encrypted_text_s, aesData!!.cipherText)
            createFile(ENCRYPTED_TEXT_FILE, aesData!!.cipherText)
        }
    }

    private fun decryptDataAES(encryptedText: ByteArray) {
        if (isAESDataValid()) {
            if (aesData != null) {
                val plainText = decryptAES(encryptedText, aesKey!!, aesData!!.ivValue)
                msgLog(DECRYPT_AES_TEXT + plainText)
                binding.txtDecryptedText.text = getString(R.string.decrypted_text_s, plainText)
            } else {
                msgToast(NOTHING_TO_DECRYPT)
            }
        }
    }

    private fun encryptDataRSA() {
        if ((rsaPublicKey == null) || text.isEmpty() || (rsaPrivateKey == null)) return msgToast("Please select the text file or generate RSA keys")
        rsaData = encryptRSA(text, publicKey = rsaPublicKey)
        createFile(ENCRYPTED_TEXT_FILE, rsaData!!.encryptedText)
        msgLog(ENCRYPTED_RSA_TEXT + rsaData!!.encryptedText)
        binding.txtEncryptedRsaText.text =
            getString(R.string.encrypted_rsa_text_s, rsaData!!.encryptedText)
    }

    private fun decryptDataRSA(encryptedText: ByteArray) {
        if ((rsaPublicKey == null)) return msgToast(GENERATE_RSA_KEYS)
        if (encryptedText.isEmpty()) return msgToast(NOTHING_TO_DECRYPT)
        val decryptedText = decryptRSA(encryptedText, rsaPrivateKey)
        msgLog(DECRYPT_RSA_TEXT + decryptedText)
        binding.txtDecryptedRsaText.text = getString(R.string.decrypted_rsa_text_s, decryptedText)
    }

    private fun getMyIntent(): Intent {
        return Intent()
            .setType("*/*")
            .setAction(Intent.ACTION_GET_CONTENT)
    }

    private fun openDataSelector(code: Int) {
        startActivityForResult(
            Intent.createChooser(getMyIntent(), SELECT_ENCRYPT_FILE),
            code
        )
    }

    private fun generateAES() {
        aesKey = generateAESKey()
        msgLog(KEY + aesKey!!.encoded)
        binding.txtSecretAESKey.text = getString(R.string.aes_key_s, aesKey!!.encoded)
        createFile(AES_KEY_FILE_NAME, aesKey!!.encoded)
    }

    private fun generateRSA() {
        val keys = generateRSAKey()
        rsaPrivateKey = keys.privateKey
        rsaPublicKey = keys.publicKey
        createFile(PRIVATE_KEY_FILE_NAME, rsaPrivateKey!!.encoded.toString())
        createFile(PUBLIC_KEY_FILE_NAME, rsaPublicKey!!.encoded.toString())
        binding.txtPrivateRsaKey.text =
            getString(R.string.rsa_private_key_s, rsaPrivateKey!!.encoded.toString())
        binding.txtPublicRsaKey.text =
            getString(R.string.rsa_public_key_s, rsaPublicKey!!.encoded.toString())
        msgLog(PUBLIC_KEY + rsaPublicKey!!.encoded)
        msgLog(PRIVATE_KEY + rsaPrivateKey!!.encoded)
    }

    private fun setDigestNumber() {
        if (rsaData != null) {
            createFile(DIGEST_MSG_FILE_NAME, rsaData!!.digestNumber)
            msgLog(DIGEST_MSG + rsaData!!.digestNumber)
            binding.txtDigestiveSum.text =
                getString(R.string.digestive_text_s, rsaData!!.digestNumber)
        } else {
            msgToast(GENERATE_ENCRYPTED_MSG_RSA)
        }
    }

    private fun digitalSigning() {
        if (rsaPrivateKey != null) {
            if (text.isEmpty()) return msgToast(SELECT_FILE)
            digitalSign = generateDigitalSign(text, rsaPrivateKey!!)
            msgLog(DIGITAL_SIGN + digitalSign)
            binding.txtDigitalSign.text = getString(R.string.signature_text_s, digitalSign)
            digitalSign?.let { createFile(DIGITAL_SIGN_FILE_NAME, it) }
        } else {
            msgToast(GENERATE_RSA_KEYS)
        }
    }

    private fun signatureVerify(digitalSignature: ByteArray) {
        if (rsaPublicKey != null) {
            val isVerified = verifyDigitalSign(text, digitalSignature, rsaPublicKey!!)
            msgToast(VERIFICATION_IS + isVerified)
            msgLog(VERIFICATION_IS + isVerified)
        } else {
            msgToast(GENERATE_RSA_KEYS)
        }
    }

    private fun createFile(fileName: String, inputText: ByteArray) {
        val file = File("${Environment.getExternalStorageDirectory()}$FILE_PATH$fileName.txt")
        file.writeBytes(inputText)
        msgToast("successfully created file ${fileName}.txt")
    }

    private fun createFile(fileName: String, inputText: String) {
        val file = File("${Environment.getExternalStorageDirectory()}$FILE_PATH$fileName.txt")
        file.writeText(inputText)
        msgToast("successfully created file ${fileName}.txt")
    }

    private fun isAESDataValid(): Boolean {
        if (text.isEmpty()) {
            msgToast(SELECT_FILE)
            return false
        }
        if (aesKey == null) {
            msgToast(CREATE_AES_KEY)
            return false
        }
        return true
    }

    private fun logData() {
        msgLog("tekst path: $textFilePath")
        msgLog("tekst: $text")
    }

    private fun msgToast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    private fun msgLog(msg: String) {
        Log.d("SADRZAJ_OVE_APLIKACIJE", msg)
    }

    companion object {
        private const val SELECT_FILE = "Select a text file"
        private const val CREATE_AES_KEY = "Create AES key"
        private const val GENERATE_RSA_KEYS = "Generate RSA keys"
        private const val GENERATE_ENCRYPTED_MSG_RSA = "Generate encrypted msg RSA"
        private const val SELECT_ENCRYPT_FILE = "Select a file to decrypt"
        private const val NOTHING_TO_DECRYPT = "Nothing to decrypt!"

        private const val DIGITAL_SIGN_FILE_NAME = "digitalniPotpis"
        private const val DIGEST_MSG_FILE_NAME = "sazetakPoruke"
        private const val PRIVATE_KEY_FILE_NAME = "privatniKljuc"
        private const val PUBLIC_KEY_FILE_NAME = "javniKljuc"
        private const val ENCRYPTED_TEXT_FILE = "kriptiraniTekst"
        private const val AES_KEY_FILE_NAME = "kljucAES"

        private const val KEY = "key: "
        private const val PUBLIC_KEY = "javni kljuc: "
        private const val PRIVATE_KEY = "privatni kljuc: "
        private const val DIGITAL_SIGN = "Digitalni potpis: "
        private const val DIGEST_MSG = "sazetak poruke: "
        private const val VERIFICATION_IS = "Verification is: "
        private const val DECRYPT_RSA_TEXT = "Dekriptirani RSA tekst: "
        private const val DECRYPT_AES_TEXT = "Dekriptirani AES tekst: "
        private const val ENCRYPTED_RSA_TEXT = "Kriptirani RSA tekst: "
        private const val ENCRYPTED_AES_TEXT = "Kriptirani AES tekst: "

        private const val FILE_PATH = "/Download/"

        const val SIGN_ALGORITHM_SHA1_RSA = "SHA1withRSA"
        const val SHA_256 = "SHA-256"
        const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
        const val AES_TRANSFORMATION = "AES/CBC/PKCS5PADDING"
        const val AES = "AES"
        const val MY_SECRET_KEY = "MySecretKey"
        const val KEY_SIZE = 1024
    }
}