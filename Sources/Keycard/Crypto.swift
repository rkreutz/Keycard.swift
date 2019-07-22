enum PBKDF2HMac {
    case sha256
    case sha512
}

class Crypto {
    static let shared = Crypto()
    
    private init() {}
    
    func pbkdf2(password: String, salt: [UInt8], iterations: Int, hmac: PBKDF2HMac) -> [UInt8] {
        [] //TODO: implement
    }
    
    func hmacSHA512(data: [UInt8], key: [UInt8]) -> [UInt8] {
        [] //TODO: implement
    }
    
    func kekkac256(_ data: [UInt8]) -> [UInt8] {
        [] //TODO: implement
    }
    
    func secp256k1PublicToEthereumAddress(_ pubKey: [UInt8]) -> [UInt8] {
        Array(kekkac256(Array(pubKey[1...]))[12...])
    }
    
    func secp256k1PublicFromPrivate(_ privKey: [UInt8]) -> [UInt8] {
        [] //TODO: implement
    }
    
    func secp256k1RecoverPublic(r: [UInt8], s: [UInt8], recId: UInt8, hash: [UInt8]) -> [UInt8] {
        [] //TODO: implement
    }
    
    func random(count: Int) -> [UInt8] {
        [] //TODO: implement
    }
}
