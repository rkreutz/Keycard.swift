import Foundation

public class CashCommandSet {
    let cardChannel: CardChannel
    
    public init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
    }
    
    public func select() throws -> CashApplicationInfo {
        let selectApplet: APDUCommand = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: Identifier.keycardCashInstanceAID.val)
        let response = try cardChannel.send(selectApplet)
        return try CashApplicationInfo(response.checkOK().data)
    }
    
    public func sign(data: [UInt8]) throws -> RecoverableSignature {
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.sign.rawValue, p1: 0, p2: 0, data: data)
        let response = try cardChannel.send(cmd)
        return try RecoverableSignature(hash: data, data: response.checkOK().data)
    }
}

