enum AppStatusTag: UInt8 {
    case template = 0xA3
}

public struct ApplicationStatus {
    public var pinRetryCount: Int
    public var pukRetryCount: Int
    public var hasMasterKey: Bool
    
    public init(_ data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        _ = try tlv.enterConstructed(tag: AppStatusTag.template.rawValue)
        pinRetryCount = try tlv.readInt()
        pukRetryCount = try tlv.readInt()
        hasMasterKey = try tlv.readBoolean()
    }
}
