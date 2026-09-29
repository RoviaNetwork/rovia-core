import Foundation

extension Foundation.Bundle {
    static let module: Bundle = {
        let mainPath = Bundle.main.bundleURL.appendingPathComponent("RoviaConfig_RoviaConfigTests.bundle").path
        let buildPath = "/private/var/folders/sp/c6ts53150j3cdgr4ty_k_7d00000gn/T/opencode/split/core-src/core/config/.build/x86_64-apple-macosx/debug/RoviaConfig_RoviaConfigTests.bundle"

        let preferredBundle = Bundle(path: mainPath)

        guard let bundle = preferredBundle ?? Bundle(path: buildPath) else {
            // Users can write a function called fatalError themselves, we should be resilient against that.
            Swift.fatalError("could not load resource bundle: from \(mainPath) or \(buildPath)")
        }

        return bundle
    }()
}