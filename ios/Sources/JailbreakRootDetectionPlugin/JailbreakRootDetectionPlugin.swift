import Foundation
import Capacitor

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(JailbreakRootDetectionPlugin)
public class JailbreakRootDetectionPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "JailbreakRootDetectionPlugin"
    public let jsName = "JailbreakRootDetection"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "jailbroken", returnType: CAPPluginReturnPromise)
    ]
    private let implementation = JailbreakRootDetection()

    @objc func jailbroken(_ call: CAPPluginCall) {
        call.resolve([
            "isJailbroken": implementation.jailbroken()
        ])
    }
}
