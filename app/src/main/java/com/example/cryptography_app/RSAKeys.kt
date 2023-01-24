package com.example.cryptography_app

import java.security.PrivateKey
import java.security.PublicKey

data class RSAKeys(
    val privateKey: PrivateKey,
    val publicKey: PublicKey
)
