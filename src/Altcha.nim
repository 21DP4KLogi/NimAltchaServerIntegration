import jester
import std/[sysrand, strutils, json]
import nimcrypto/[sha2, hmac]

const complexity: uint = 1_000_000
const hmacKey = "password123"

routes:
  get "/new":
    
    var randomBytes: seq[byte]

    # Generating salt
    randomBytes = urandom(5)
    var salt: string
    for i in randomBytes:
      salt.add i.toHex
    
    # Generating secret number
    randomBytes = urandom(8)
    var randomNumber: uint
    for i in 0..(randomBytes.len - 1):
      randomNumber += randomBytes[i]
      randomNumber = randomNumber shl 8
    let secretNumber = randomNumber mod complexity

    # Generating challenge hash
    let challenge = $sha256.digest(salt & $secretNumber)

    # Generating server signature
    let signature = $sha256.hmac(hmacKey, challenge)

    resp(%* {
      "algorithm": "SHA-256",
      "challenge": challenge,
      "salt": salt,
      "signature": signature,
    })

  post "/submit":
    resp Http200
