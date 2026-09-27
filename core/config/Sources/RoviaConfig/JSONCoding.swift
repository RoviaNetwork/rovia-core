import Foundation

let canonicalStructuralDecodingKey = CodingUserInfoKey(rawValue: "RoviaConfig.structuralDecoding")!

public enum JSONCoding {
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    public static func structuralDecoder() -> JSONDecoder {
        let decoder = decoder()
        decoder.userInfo[canonicalStructuralDecodingKey] = true
        return decoder
    }

    public static func strictEncoder() -> JSONEncoder {
        encoder()
    }

    public static func strictDecoder() -> JSONDecoder {
        decoder()
    }
}

enum CanonicalCodingSupport {
    private struct DynamicCodingKey: CodingKey {
        let stringValue: String
        let intValue: Int?

        init?(stringValue: String) {
            self.stringValue = stringValue
            intValue = nil
        }

        init?(intValue: Int) {
            stringValue = String(intValue)
            self.intValue = intValue
        }
    }

    static func rejectUnknownKeys(
        _ decoder: Decoder,
        allowed: Set<String>,
        description: String
    ) throws {
        let container = try decoder.container(keyedBy: DynamicCodingKey.self)
        if let unknown = container.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
            throw DecodingError.dataCorruptedError(
                forKey: unknown,
                in: container,
                debugDescription: description
            )
        }
    }
}
