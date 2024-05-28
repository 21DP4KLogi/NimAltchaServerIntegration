import jester
import std/[sysrand, strutils, json, base64]
import nimcrypto/[sha2, hmac]

const complexity: uint = 1_000
const hmacKey = "password123"

routes:
  get "/new":
    
    var randomBytes: seq[byte]

    # Generating salt
    randomBytes = urandom(5)
    var salt: string
    for i in randomBytes:
      salt.add i.toHex
    salt = salt.toLower()
    
    # Generating secret number
    randomBytes = urandom(8)
    var randomNumber: uint
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
    let data = decode(request.body.parseJson["payload"].getStr).parseJson()
    echo data

    let alg_ok = data["algorithm"].getStr == "SHA-256"

    let challenge_ok = data["challenge"].getStr == toLower($sha256.digest(data["salt"].getStr & $data["number"].getInt))

    let signature_ok = data["signature"].getStr == toLower($sha256.hmac(hmacKey, data["challenge"].getStr))
    
    if alg_ok and challenge_ok and signature_ok:
      # Don't know why, but the widget requires a JSON response to not throw an error
      resp Http200, $(%* {"foo": "bar"})
    else:
      resp Http400
