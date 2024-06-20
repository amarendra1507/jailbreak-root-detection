package com.smartwinnr.plugins.jailbreakrootdetection;

import android.util.Log;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class JailbreakRootDetection {

    public String echo(String value) {
        Log.i("Echo", value);
        return value;
    }

    public Boolean jailbroken(Context context) {
        Log.i("Echo", "Checking root detectection");
        boolean isJailbroken = checkRootMethod1() || checkRootMethod2() || checkRootMethod3() || checkRootBypassApps(context) || checkDirPermissions() || checkforOverTheAirCertificates();
        return isJailbroken;
    }


    private boolean checkRootMethod1() {
        String[] paths = {
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/bin/su"
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private boolean checkRootMethod2() {
        List<String> commands = new ArrayList<>();
        commands.add("which su");
        commands.add("/system/xbin/which su");
        commands.add("/system/bin/which su");
        return executeCommands(commands);
    }

    private boolean checkRootMethod3() {
        String buildTags = Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }

    private boolean executeCommands(List<String> commands) {
        try {
            for (String command : commands) {
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
                if (in.readLine() != null) return true;
                in.close();
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

     private boolean checkRootBypassApps(final Context context) {
        List<String> rootAppsPackages = Arrays.asList(
                "com.topjohnwu.magisk",                // Magisk
                "eu.chainfire.supersu",                // SuperSU
                "com.koushikdutta.superuser",          // Superuser
                "com.noshufou.android.su",             // Superuser (older version)
                "com.kingroot.kinguser",               // KingRoot
                "com.kingouser.com",                   // KingRoot
                "com.kingroot.kinguser.activity",      // Kingoroot
                "com.kingoroot.kingoapp",              // Kingoroot
                "com.alephzain.framaroot",             // Framaroot
                "com.baidu.easyroot",                  // Baidu Root
                "com.oneclickroot",                    // One Click Root
                "com.shuame.rootgenius",               // Root Genius
                "com.mgyun.shua.su",                   // iRoot
                "com.mgyun.shua",                      // iRoot
                "com.geohot.towelroot",                // Towelroot
                "com.root.master",                     // Root Master
                "com.z4mod.z4root",                    // Z4Root
                "com.saurik.Cydia",                    // Cydia
                "stericson.busybox",                   // BusyBox
                "stericson.busybox.donate",             // BusyBox (Donate) 
                "com.zachspong.temprootremovejb",
                "com.ramdroid.appquarantine",
                "eu.chainfire.stickmount",
                "eu.chainfire.mobileodin.pro",
                "eu.chainfire.liveboot",
                "eu.chainfire.pryfi",
                "eu.chainfire.adbd",
                "eu.chainfire.recently",
                "eu.chainfire.flash",
                "eu.chainfire.stickmount.pro",
                "eu.chainfire.triangleaway",
                "org.adblockplus.android"
        );
        return isAnyPackageInstalled(rootAppsPackages, context);
    }

    private boolean isAnyPackageInstalled(List<String> packages, final Context context) {
        PackageManager pm = context.getPackageManager();
        for (String packageName : packages) {
            try {
                pm.getPackageInfo(packageName, 0);
                return true;  // Package found
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found
            }
        }
        return false;
    }

     private boolean checkDirPermissions() {
        boolean isWritableDir;
        boolean isReadableDataDir;
        boolean result = false;
        List<String> pathShouldNotWritable = Arrays.asList(
            "/data",
            "/",
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc"
        );

        for (String dirName : pathShouldNotWritable) {
            final File currentDir = new File(dirName);

            isWritableDir = currentDir.exists() && currentDir.canWrite();
            isReadableDataDir = (dirName.equals("/data") && currentDir.canRead());

            if (isWritableDir || isReadableDataDir) {
                result = true;
            }
        }
        return result;
    }

    private boolean checkforOverTheAirCertificates() {
        File otacerts = new File("/etc/security/otacerts.zip");
        boolean exist = otacerts.exists();
        boolean result = !exist;
        return result;
    }


}
