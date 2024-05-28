# This code is a Nim implementation of the Algorithms described in https://altcha.org/docs/server-integration/

# Note: the frontend widget works only with lowercase letters, but nimcrypto hashing gives UPPERCASE
# strings, so that's why toLower() is used

import jester
import std/[sysrand, strutils, json, base64]
import nimcrypto/[sha2, hmac]

# The Altcha complexity, described here: https://altcha.org/docs/complexity/
# Make sure to change the maxnumber in the frontend widget to a higher number
const complexity: uint = 10_000

# The HMAC key used to sign the challenge, you should probably use a more secure key than this example
const hmacKey = "password123"

routes:

  get "/new":
    
    # Wanted to reuse the name, so I made it variable
    var randomBytes: seq[byte]

    # Generating salt
    # 5 bytes chosen as when it gets converted to hexadecimal, its length doubles into the recommended 10 chars
    randomBytes = urandom(5)
    var salt: string
    # Converts the byte sequence to a hexadecimal string
    for i in randomBytes:
      salt.add i.toHex
    salt = salt.toLower()
    
    # Generating secret number
    # This section is just a Random Number Generator, but created with secure random, unlike the std/random library
    # 8 Bytes chosen because that is 64 bits
    randomBytes = urandom(8)
    var randomNumber: uint
    # Assembles an array of bytes (randomBytes) into a single number (randomNumber)
    for i in 0..(randomBytes.len - 1):
      randomNumber += randomBytes[i]
      randomNumber = randomNumber shl 8
    let secretNumber = randomNumber mod complexity

    # Generating challenge hash
    let challenge = toLower($sha256.digest(salt & $secretNumber))

    # Generating server signature
    let signature = toLower($sha256.hmac(hmacKey, challenge))

    resp(%* {
      "algorithm": "SHA-256",
      "challenge": challenge,
      "salt": salt,
      "signature": signature,
    })

  post "/submit":
    # Parses the body of the request, finds the "payload" field, decodes it from Base64, and the parses the resulting JSON
    let data = decode(request.body.parseJson["payload"].getStr).parseJson()

    let alg_ok = data["algorithm"].getStr == "SHA-256"

    let challenge_ok = data["challenge"].getStr == toLower($sha256.digest(data["salt"].getStr & $data["number"].getInt))

    let signature_ok = data["signature"].getStr == toLower($sha256.hmac(hmacKey, data["challenge"].getStr))
    
    if alg_ok and challenge_ok and signature_ok:
      # Don't know why, but the widget requires a JSON response to not throw an error
      resp Http200, $(%* {"foo": "bar"})
    else:
      resp Http400
