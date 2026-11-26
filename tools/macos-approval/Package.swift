// swift-tools-version: 5.9
import PackageDescription

let package = Package(name: "TernSSHApproval", platforms: [.macOS(.v13)], targets: [
    .target(name: "ApprovalCore"),
    .executableTarget(name: "TernSSHApproval", dependencies: ["ApprovalCore"]),
    .testTarget(name: "ApprovalCoreTests", dependencies: ["ApprovalCore"]),
])
