// Build: swiftc scripts/macos_monitor.swift -o .tools/macos-monitor
// Usage: .tools/macos-monitor en0 2412
// Disassociates this dedicated collector radio before selecting the DUT channel.
import CoreWLAN
import Foundation

if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--check" {
    let name = CommandLine.arguments[2]
    let requestedSSID = CommandLine.arguments[3]
    guard let current = CWWiFiClient.shared().interface(withName: name), current.interfaceMode() == .station else { exit(1) }
    if let actual = current.ssid(), actual != requestedSSID { exit(1) }
    let check = Process()
    let output = Pipe()
    check.executableURL = URL(fileURLWithPath: "/usr/sbin/ipconfig")
    check.arguments = ["getsummary", name]
    check.standardOutput = output
    try check.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    check.waitUntilExit()
    let summary = String(data: data, encoding: .utf8) ?? ""
    guard summary.contains("LinkStatusActive : TRUE") && summary.contains("State : BOUND") else { exit(1) }
    let internet = Process()
    internet.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    internet.arguments = ["--fail", "--silent", "--show-error", "--head", "--connect-timeout", "2", "--max-time", "3", "--output", "/dev/null", "https://example.com/"]
    internet.standardError = FileHandle.nullDevice
    try internet.run();internet.waitUntilExit()
    guard internet.terminationStatus == 0 else { exit(1) }
    print("Collector restored to station mode, DHCP and internet; preferred network: \(requestedSSID)")
    if current.ssid() == nil { print("macOS redacts the associated SSID; exact SSID verification unavailable") }
    exit(0)
}
if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--restore" {
    let name = CommandLine.arguments[2]
    let requestedSSID = CommandLine.arguments[3]
    guard let iface = CWWiFiClient.shared().interface(withName: name) else {
        fputs("interface unavailable\n", stderr); exit(1)
    }
    let preferences = Process()
    let pipe = Pipe()
    preferences.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
    preferences.arguments = ["-listpreferredwirelessnetworks", name]
    preferences.standardOutput = pipe
    try preferences.run(); preferences.waitUntilExit()
    let saved = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let networks = saved.split(separator: "\n").dropFirst().map { $0.trimmingCharacters(in: .whitespaces) }
    guard networks.first == requestedSSID else {
        fputs("Restore target must be the first saved Wi-Fi network: \(requestedSSID)\n", stderr)
        exit(1)
    }
    // Allow normal autojoin first; power-cycle only if it has not recovered.
    var powerCycled = false
    let began = Date()
    let deadline = Date().addingTimeInterval(45)
    while Date() < deadline {
        let check = Process()
        check.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        check.arguments = ["--check", name, requestedSSID]
        try check.run();check.waitUntilExit()
        if check.terminationStatus == 0 { exit(0) }
        if !powerCycled && Date().timeIntervalSince(began) > 10 {
            do {
                try iface.setPower(false)
                Thread.sleep(forTimeInterval: 0.5)
                try iface.setPower(true)
                powerCycled = true
            } catch {
                fputs("Wi-Fi recovery failed: \(error)\n", stderr); exit(1)
            }
        }
        Thread.sleep(forTimeInterval: 0.5)
    }
    fputs("Wi-Fi did not recover a normal station connection\n", stderr)
    exit(1)
}
if CommandLine.arguments.count != 3 {
    fputs("usage: macos-monitor INTERFACE FREQUENCY_MHZ\n", stderr)
    exit(2)
}
guard let frequency = Int(CommandLine.arguments[2]),
      let iface = CWWiFiClient.shared().interface(withName: CommandLine.arguments[1]) else {
    fputs("invalid interface or frequency\n", stderr)
    exit(2)
}
let candidates = iface.supportedWLANChannels() ?? []
guard let channel = candidates.first(where: { channel in
    let n = channel.channelNumber
    switch channel.channelBand {
    case .band2GHz: return frequency == (n == 14 ? 2484 : 2407 + 5 * n)
    case .band5GHz: return frequency == 5000 + 5 * n
    case .band6GHz: return frequency == 5950 + 5 * n
    default: return false
    }
}) else {
    fputs("frequency unsupported by collector\n", stderr)
    exit(2)
}
iface.disassociate()
do {
    try iface.setWLANChannel(channel)
    guard iface.wlanChannel()?.channelNumber == channel.channelNumber else {
        fputs("channel selection did not take effect\n", stderr)
        exit(1)
    }
    print("Collector tuned to \(frequency) MHz, channel \(channel.channelNumber)")
} catch {
    fputs("channel selection failed: \(error)\n", stderr)
    exit(1)
}
