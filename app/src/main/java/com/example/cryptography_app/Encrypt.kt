package com.example.cryptography_app

data class Encrypt(
    val plainText: String,
    val cipherText: ByteArray,
    val ivValue: ByteArray
)
