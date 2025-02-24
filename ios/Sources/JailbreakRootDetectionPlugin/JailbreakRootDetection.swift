import Foundation
import UIKit
import Darwin // fork
import MachO // dyld

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
            "/Applications/WinterBoard.app",
            "/var/mobile/Library/Preferences/ABPattern", // A-Bypass
              "/usr/lib/ABDYLD.dylib", // A-Bypass,
              "/usr/lib/ABSubLoader.dylib", // A-Bypass
              "/usr/sbin/frida-server", // frida
              "/etc/apt/sources.list.d/electra.list", // electra
              "/etc/apt/sources.list.d/sileo.sources", // electra
              "/.bootstrapped_electra", // electra
              "/usr/lib/libjailbreak.dylib", // electra
              "/jb/lzma", // electra
              "/.cydia_no_stash", // unc0ver
              "/.installed_unc0ver", // unc0ver
              "/jb/offsets.plist", // unc0ver
              "/usr/share/jailbreak/injectme.plist", // unc0ver
              "/etc/apt/undecimus/undecimus.list", // unc0ver
              "/var/lib/dpkg/info/mobilesubstrate.md5sums", // unc0ver
              "/Library/MobileSubstrate/MobileSubstrate.dylib",
              "/jb/jailbreakd.plist", // unc0ver
              "/jb/amfid_payload.dylib", // unc0ver
              "/jb/libjailbreak.dylib", // unc0ver
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
              "/Applications/Sileo.app",
              "/var/binpack",
              "/Library/PreferenceBundles/LibertyPref.bundle",
              "/Library/PreferenceBundles/ShadowPreferences.bundle",
              "/Library/PreferenceBundles/ABypassPrefs.bundle",
              "/Library/PreferenceBundles/FlyJBPrefs.bundle",
              "/Library/PreferenceBundles/Cephei.bundle",
              "/Library/PreferenceBundles/SubstitutePrefs.bundle",
              "/Library/PreferenceBundles/libhbangprefs.bundle",
              "/usr/lib/libhooker.dylib",
              "/usr/lib/libsubstitute.dylib",
              "/usr/lib/substrate",
              "/usr/lib/TweakInject",
              "/var/binpack/Applications/loader.app", // checkra1n
              "/Applications/FlyJB.app", // Fly JB X
              "/Applications/Zebra.app", // Zebra
              "/Library/BawAppie/ABypass", // ABypass
              "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist", // SSL Killswitch
              "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist", // PreferenceLoader
              "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib", // PreferenceLoader
              "/Library/MobileSubstrate/DynamicLibraries", // DynamicLibraries directory in general
              "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
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
        
        let jailbreakStatus =  
        detectSuspiciousProcesses() ||
        checkFork() ||
        checkDYLD() ||
        checkURLSchemes() || checkSuspiciousObjCClasses();
        
        print("Jailbreak Status", jailbreakStatus);
        
        
        
        if (jailbreakStatus) {
            return true;
        }

        #endif
        
        return false;
        
    }
    
//    func isDeviceJailbroken() -> Bool {
//        // Call the system() function with NULL argument
//        let result = system(nil)
//        
//        // On a non-jailbroken device, result should be 0
//        // On a jailbroken device, result should be 1
//        return result == 1
//    }

    func detectSuspiciousProcesses() -> Bool {
        print("**** Checking suspicius process is running or not");
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var size = 0

        // Get the size of the process list
        if sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) != 0 {
            return false
        }

        let processListPointer = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<kinfo_proc>.alignment)
        defer {
            processListPointer.deallocate()
        }

        // Get the actual process list
        if sysctl(&mib, UInt32(mib.count), processListPointer, &size, nil, 0) != 0 {
            return false
        }

        let procList = processListPointer.bindMemory(to: kinfo_proc.self, capacity: size / MemoryLayout<kinfo_proc>.stride)
        let processCount = size / MemoryLayout<kinfo_proc>.stride

        for i in 0..<processCount {
            var process = procList[i]
            let processName = withUnsafePointer(to: &process.kp_proc.p_comm) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                    String(cString: $0)
                }
            }

            // Add known suspicious processes to check here
            let suspiciousProcesses = ["Cydia", "sshd", "apt"]
            if suspiciousProcesses.contains(processName) {
                return true
            }
        }

        return false
    }
    
    func checkFork() -> Bool {
        let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
        let forkPtr = dlsym(pointerToFork, "fork")
        typealias ForkType = @convention(c) () -> pid_t
        let fork = unsafeBitCast(forkPtr, to: ForkType.self)
        let forkResult = fork()
            
        if forkResult >= 0 {
            if forkResult > 0 {
                kill(forkResult, SIGTERM)
            }
            return true // Fork successfull so the device might be jailbroken
        }
        
        return false
      }
    
    func checkDYLD() -> Bool {
        let suspiciousLibraries: Set<String> = [
          "systemhook.dylib", // Dopamine - hide jailbreak detection https://github.com/opa334/Dopamine/blob/dc1a1a3486bb5d74b8f2ea6ada782acdc2f34d0a/Application/Dopamine/Jailbreak/DOEnvironmentManager.m#L498
          "SubstrateLoader.dylib",
          "SSLKillSwitch2.dylib",
          "SSLKillSwitch.dylib",
          "MobileSubstrate.dylib",
          "TweakInject.dylib",
          "CydiaSubstrate",
          "cynject",
          "CustomWidgetIcons",
          "PreferenceLoader",
          "RocketBootstrap",
          "WeeLoader",
          "/.file", // HideJB (2.1.1) changes full paths of the suspicious libraries to "/.file"
          "libhooker",
          "SubstrateInserter",
          "SubstrateBootstrap",
          "ABypass",
          "FlyJB",
          "Substitute",
          "Cephei",
          "Electra",
          "AppSyncUnified-FrontBoard.dylib",
          "Shadow",
          "FridaGadget",
          "frida",
          "libcycript"
        ]
        
        for index in 0..<_dyld_image_count() {
          let imageName = String(cString: _dyld_get_image_name(index))
          
          // The fastest case insensitive contains check.
          for library in suspiciousLibraries where imageName.localizedCaseInsensitiveContains(library) {
            print("Dopamine Detected")
            return true
          }
        }
        
        return false
      }
    
    func checkSuspiciousObjCClasses() -> Bool {
        if let shadowRulesetClass = objc_getClass("ShadowRuleset") as? NSObject.Type {
          let selector = Selector(("internalDictionary"))
          if class_getInstanceMethod(shadowRulesetClass, selector) != nil {
            return true
          }
        }
        return false
      }
    
    func checkURLSchemes() -> Bool {
        let urlSchemes = [
          "undecimus://",
          "sileo://",
          "zbra://",
          "filza://"
        ]
        return canOpenUrlFromList(urlSchemes: urlSchemes)
      }
    
    func canOpenUrlFromList(urlSchemes: [String]) -> Bool {
        for urlScheme in urlSchemes {
          if let url = URL(string: urlScheme) {
            if UIApplication.shared.canOpenURL(url) {
              return true
            }
          }
        }
        return false
      }


}
