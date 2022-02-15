import Foundation

public enum CardError: Error {
    case invalidAID
    case invalidPIN
    case invalidPUK
    case invalidPairingPassword
    case wrongPIN(retryCounter: Int)
    case wrongPUK(retryCounter: Int)
    case unrecoverableSignature
    case invalidState
    case notPaired
    case pinBlocked
    case invalidAuthData
    case invalidMac
    case invalidRequestData
    case invalidResponseData(TLVError)
    case unexpectedSW(StatusWord)
    case unexpectedError(Error)
    case privateKeyCannotBeExported
    case invalidKeyPath(KeyPathError)
    case payloadTooLong
}
