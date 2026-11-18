// swift-tools-version: 6.0
// Krypto-Kern der europe.social-Apps (iOS, iPadOS, Mac) für Direktnachrichten. Ohne Fremdpakete, nur CryptoKit.
import PackageDescription

let package = Package(
    name: "EuropeKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "EuropeKit", targets: ["EuropeKit"]),
    ],
    targets: [
        .target(name: "EuropeKit"),
        .testTarget(name: "EuropeKitTests", dependencies: ["EuropeKit"], resources: [.copy("Daten")]),
    ]
)
