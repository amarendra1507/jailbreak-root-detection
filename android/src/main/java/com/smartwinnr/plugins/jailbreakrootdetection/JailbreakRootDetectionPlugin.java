package com.smartwinnr.plugins.jailbreakrootdetection;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import android.content.Context;

@CapacitorPlugin(name = "JailbreakRootDetection")
public class JailbreakRootDetectionPlugin extends Plugin {

    private JailbreakRootDetection implementation = new JailbreakRootDetection();

    @PluginMethod
    public void echo(PluginCall call) {
        String value = call.getString("value");

        JSObject ret = new JSObject();
        ret.put("value", implementation.echo(value));
        call.resolve(ret);
    }

    @PluginMethod
    public void jailbroken(PluginCall call) {
        String verificationKey = call.getString("verificationKey");
        String decryptionKey = call.getString("decryptionKey");
        JSObject ret = new JSObject();
        ret.put("isJailbroken", implementation.jailbroken(getContext(), verificationKey, decryptionKey));
        call.resolve(ret);
    }
}
