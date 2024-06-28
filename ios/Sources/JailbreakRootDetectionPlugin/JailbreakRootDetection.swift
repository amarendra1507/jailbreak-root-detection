import Foundation
import UIKit

@objc public class JailbreakRootDetection: NSObject {
    @objc public func jailbroken() -> Bool {

        #if !TARGET_IPHONE_SIMULATOR
        
        // Check if fork() succeeds
        var pid: pid_t = 0
        let status = posix_spawn(&pid, "/bin/ls", nil, nil, nil, nil)
        if status == 0 {
            return true
        }
        
        // List of paths indicating a jailbreak
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/private/var/stash",
            "/private/var/lib/apt",
            "/private/var/tmp/cydia.log",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/var/log/syslog",
            "/var/tmp/cydia.log",
            "/bin/sh",
            "/usr/libexec/ssh-keysign",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/etc/ssh/sshd_config",
            "/Applications/RockApp.app",
            "/Applications/Icy.app",
            "/Applications/WinterBoard.app",
            "/Applications/SBSettings.app",
            "/Applications/MxTube.app",
            "/Applications/IntelliScreen.app",
            "/Applications/FakeCarrier.app",
            "/Applications/blackra1n.app",
            "/usr/sbin/frida-server",
            "/etc/apt/sources.list.d/electra.list",
            "/etc/apt/sources.list.d/sileo.sources",
            "/.bootstrapped_electra",
            "/usr/lib/libjailbreak.dylib",
            "/jb/lzma",
            "/.cydia_no_stash",
            "/.installed_unc0ver",
            "/jb/offsets.plist",
            "/usr/share/jailbreak/injectme.plist",
            "/etc/apt/undecimus/undecimus.list",
            "/var/lib/dpkg/info/mobilesubstrate.md5sums",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/jb/jailbreakd.plist",
            "/jb/amfid_payload.dylib",
            "/jb/libjailbreak.dylib",
            "/usr/libexec/cydia/firmware.sh",
            "/var/lib/cydia",
            "/etc/apt",
            "/private/var/lib/apt",
            "/private/var/Users/",
            "/var/log/apt",
            "/Applications/Cydia.app",
            "/private/var/stash",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/cache/apt/",
            "/private/var/log/syslog",
            "/private/var/tmp/cydia.log",
            "/Applications/Icy.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/blackra1n.app",
            "/Applications/SBSettings.app",
            "/Applications/FakeCarrier.app",
            "/Applications/WinterBoard.app",
            "/Applications/IntelliScreen.app",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app"
        ]
        print("**** Checking for malicious app installed ***");
        // Check for the existence of jailbreak paths
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        print("**** Checking file write ***");
        // Attempt to write to a restricted area
        let testString = "This is a test."
        do {
            try testString.write(toFile: "/private/jailbreak.txt", atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: "/private/jailbreak.txt")
            return true
        } catch {
            // If write failed, device might not be jailbroken
        }
        
        print("**** Checking Cydia URL ***");
        // Check if Cydia URL scheme can be opened
        if let url = URL(string: "cydia://package/com.example.package"), UIApplication.shared.canOpenURL(url) {
            return true
        }
        
        #endif
        
        return false
    }
}
