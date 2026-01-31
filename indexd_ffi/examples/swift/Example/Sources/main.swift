import Foundation
import SiaSDK

// MARK: - Logger Implementation

final class PrintLogger: Logger, @unchecked Sendable {
    func debug(msg: String) {
        print("DEBUG \(msg)")
    }

    func info(msg: String) {
        print("INFO \(msg)")
    }

    func warn(msg: String) {
        print("WARNING \(msg)")
    }

    func error(msg: String) {
        print("ERROR \(msg)")
    }
}

// MARK: - Reader/Writer Implementations
//
// NOTE: These implementations use @unchecked Sendable for simplicity in this
// single-threaded example. For production code with concurrent access, use
// proper synchronization (Actor, Mutex, or @MainActor isolation).

final class BytesReader: Reader, @unchecked Sendable {
    private let data: Data
    private var offset: Int = 0
    private let chunkSize: Int

    init(data: Data, chunkSize: Int = 65536) {
        self.data = data
        self.chunkSize = chunkSize
    }

    func read() async throws -> Data {
        if offset >= data.count {
            return Data()  // EOF - return empty data
        }

        let end = min(offset + chunkSize, data.count)
        let chunk = data[offset..<end]
        offset = end
        return Data(chunk)
    }
}

final class BytesWriter: Writer, @unchecked Sendable {
    private var buffer = Data()

    func write(data: Data) async throws {
        print("BytesWriter.write called with \(data.count) bytes")
        if !data.isEmpty {
            buffer.append(data)
            print("BytesWriter buffer now has \(buffer.count) bytes")
        }
    }

    func getData() -> Data {
        print("BytesWriter.getData called, buffer has \(buffer.count) bytes")
        return buffer
    }
}

// MARK: - Main

@main
struct SiaSDKExample {
    static func main() async {
        // Set up logging
        setLogger(logger: PrintLogger(), level: "debug")

        let appId = Data(repeating: 0x01, count: 32)
        let indexerUrl = ProcessInfo.processInfo.environment["SIA_INDEXER_URL"] ?? "https://app.sia.storage"

        do {
            let builder = try Builder(indexerUrl: indexerUrl)

            _ = try await builder.requestConnection(meta: AppMeta(
                id: appId,
                name: "swift example",
                description: "an example app",
                serviceUrl: "https://example.com",
                logoUrl: nil,
                callbackUrl: nil
            ))

            let responseUrl = try builder.responseUrl()
            print("Please approve connection: \(responseUrl)")

            let approvedBuilder = try await builder.waitForApproval()

            print("Enter mnemonic (or press Enter to generate new):")
            var mnemonic = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if mnemonic.isEmpty {
                mnemonic = generateRecoveryPhrase()
                // WARNING: Never print recovery phrases in production code!
                // This is only for demonstration purposes.
                print("Generated mnemonic: \(mnemonic)")
            }

            let sdk = try await approvedBuilder.register(mnemonic: mnemonic)

            // Store the app key for later use
            let appKey = sdk.appKey()
            let appKeyData = appKey.export()
            print("App registered: \(appKeyData.base64EncodedString())")

            print("Connected to indexer")

            // Packed upload example
            let uploadStart = Date()
            let upload = await sdk.uploadPacked(options: UploadOptions())

            for i in 0..<10 {
                let data = "hello, world \(i)!".data(using: .utf8)!
                let reader = BytesReader(data: data)
                let size = try await upload.add(reader: reader)
                let remaining = try await upload.remaining()
                print("upload \(i) added \(size) bytes (\(remaining) remaining)")
            }

            let objects = try await upload.finalize()
            let uploadElapsed = Date().timeIntervalSince(uploadStart)
            print("Upload finished \(objects.count) objects in \(String(format: "%.2f", uploadElapsed))s")

            // Download example
            guard let lastObject = objects.last else {
                print("No objects were uploaded")
                return
            }
            let downloadStart = Date()
            let writer = BytesWriter()
            try await sdk.download(w: writer, object: lastObject, options: DownloadOptions())
            let downloadElapsed = Date().timeIntervalSince(downloadStart)
            let downloadedData = writer.getData()
            print("Downloaded object \(lastObject.id()) with \(downloadedData.count) bytes in \(String(format: "%.2f", downloadElapsed))s")

            if let content = String(data: downloadedData, encoding: .utf8) {
                print("Content: \(content)")
            }

        } catch {
            print("Error: \(error)")
        }
    }
}
