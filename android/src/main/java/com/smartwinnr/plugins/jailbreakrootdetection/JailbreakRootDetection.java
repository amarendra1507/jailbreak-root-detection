package com.smartwinnr.plugins.jailbreakrootdetection;

import android.util.Log;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Scanner;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import android.util.Base64;
import androidx.appcompat.app.AppCompatActivity;
import java.io.OutputStreamWriter;


public class JailbreakRootDetection extends AppCompatActivity {

    private static final String TAG = "JailbreakRootDetection";
    static final String BINARY_SU = "su";
    static final String BINARY_BUSYBOX = "busybox";
    private boolean isJailbroken = false;
    public String echo(String value) {
        Log.i("Echo", value);
        return value;
    }

    public Boolean jailbroken(Context context, String verificationKey, String decryptionKey) {
        Log.i("JailbreakRootDetection", "Checking root detectection");

        boolean rootMethod1Result = checkRootMethod1();
        boolean checkRootMethod2Result = checkRootMethod2();
        boolean checkRootMethod3Result = checkRootMethod3();
        boolean checkRootBypassAppsResult = checkRootBypassApps(context);
        boolean checkKeyLoggerAppsResult = checkKeyLoggerApps(context);
        boolean checkDirPermissionsResult = checkDirPermissions();
        boolean checkforOverTheAirCertificatesResult = checkforOverTheAirCertificates();
        boolean checkForBinaryResultSu = checkForBinary(BINARY_SU);
        boolean checkForDangerousProps = checkForDangerousProps();
        boolean checkForRWPathsResult = checkForRWPaths();
        boolean checkSuResult = checkSuExists();
        boolean checkForMagiskBinaryResult = checkForMagiskBinary();

        Log.i("JailbreakRootDetection", "Dangerous File " + rootMethod1Result);
        Log.i("JailbreakRootDetection", "Dangerous Command " + checkRootMethod2Result);
        Log.i("JailbreakRootDetection", "Test Keys " + checkRootMethod3Result);
        Log.i("JailbreakRootDetection", "RootBypass App Check " + checkRootBypassAppsResult);
        Log.i("JailbreakRootDetection", "Key Logger App Check " + checkKeyLoggerAppsResult);
        Log.i("JailbreakRootDetection", "Directory Permission " + checkDirPermissionsResult);
        Log.i("JailbreakRootDetection", "OTA Cert "+ checkforOverTheAirCertificatesResult);
        Log.i("JailbreakRootDetection", "SU Binary "+ checkForBinaryResultSu);
        Log.i("JailbreakRootDetection", "Dangerous Properties " + checkForDangerousProps);
        Log.i("JailbreakRootDetection", "Read/Write Path Check "+ checkForRWPathsResult);
        Log.i("JailbreakRootDetection", "SU Commnad Execution "+ checkSuResult);
        Log.i("JailbreakRootDetection", "Magisk Binary "+ checkForMagiskBinaryResult);

        boolean isJailbroken =
                rootMethod1Result ||
                checkRootMethod2Result ||
                checkRootMethod3Result ||
                checkRootBypassAppsResult ||
                checkKeyLoggerAppsResult ||
                checkDirPermissionsResult ||
                checkforOverTheAirCertificatesResult ||
                checkForBinaryResultSu ||
                checkForDangerousProps ||
                checkForRWPathsResult ||
                checkSuResult ||
                checkForMagiskBinaryResult;

         CompletableFuture<Boolean> future = performPlayIntegrityCheckAsync(context, verificationKey, decryptionKey);
         //  Apply the device integrity test then send the result to the app
         try {
             boolean googlePlayIntegrityCheck = future.get(); // This will block until the future completes
             Log.i(TAG, "Is device jailbroken: " + isJailbroken);
             isJailbroken = googlePlayIntegrityCheck || isJailbroken;
         } catch (InterruptedException | ExecutionException e) {
             Log.i(TAG, "An error occurred: " + e.getMessage());
         }
        isDeviceRooted();
        Log.i("JailbreakRootDetection", "Jailbreak Detection Completed");
        return isJailbroken;
    }

    public static boolean isDeviceRooted() {
        String[] commands = {
                "which su",
                "ls -l /sbin/su /system/bin/su /system/xbin/su /data/local/xbin/su /data/local/bin/su /system/sd/xbin/su /system/bin/failsafe/su /data/local/su",
                "ls -l /system/app/Superuser.apk /system/app/SuperSU.apk /system/app/Magisk.apk",
                "which busybox",
                "which magisk",
                "ls -l /sbin/.magisk",
                "ls -l /system/xbin/daemonsu /system/xbin/supolicy",
                "cat /init.rc | grep 'su'",
                "cat /init.environ.rc | grep 'su'",
                "pm list packages | grep 'superuser'",
                "pm list packages | grep 'supersu'",
                "pm list packages | grep 'magisk'"
        };

        for (String command : commands) {
            if (executeCommand(command)) {
                return true; // If any command indicates root, return true
            }
        }

        return false;
    }

    private static boolean executeCommand(String command) {
        Log.i("executeCommand", String.valueOf(command));
        try {
            Process process = Runtime.getRuntime().exec(command);
            Log.i("executeCommand", String.valueOf(process));
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output;
            Log.i("executeCommand", String.valueOf(in.readLine()));
            while ((output = in.readLine()) != null) {
                Log.i("executeCommand", String.valueOf(output));
                if (!output.isEmpty()) {
                    return true; // If any output is received, consider it as an indication of root
                }
            }
            in.close();
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


    private boolean checkRootMethod1() {
        String[] paths = {
                "/sbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/system/xbin/daemonsu",
                "/system/sd/xbin/su",
                "/system/usr/we-need-root/su-backup",
                "/system/bin/busybox",
                "/system/xbin/busybox",
                "/sbin/busybox",
                "/system/su",
                "/data/local/xbin/busybox",
                "/data/local/bin/busybox",
                "/data/local/busybox",
                "/su/bin/busybox",
                "/system/bin/su",
                "/system/xbin/su",
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
        Log.i("checkRootBypassApps",  "Root Bypassapp checking ");
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

    private boolean checkKeyLoggerApps(final Context context) {
        Log.i("checkKeyLoggerApps",  "Key Logger App Checking");
        List<String> rootAppsPackages = Arrays.asList(
                "com.abifog.lokiboard",
                "apk.typingrecorder",
                "com.gpow.keylogger",
                "com.onemanarmy.keylogger",
                "com.mni.password.manager.keylogger",
                "com.AwamiSolution.smartkeylogger",
                "monitor.mubeen.androidkeylogger",
                "com.as.keylogger"
        );
        return isAnyPackageInstalled(rootAppsPackages, context);
    }

    private boolean isAnyPackageInstalled(List<String> packages, final Context context) {
        PackageManager pm = context.getPackageManager();
        for (String packageName : packages) {
            try {
                PackageInfo isPackageInstalled = pm.getPackageInfo(packageName, 0);
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

            Log.i("currentDir", String.valueOf(currentDir));
            Log.i("exists", String.valueOf(currentDir.exists()));
            Log.i("canWrite", String.valueOf(currentDir.canWrite()));
            Log.i("canRead", String.valueOf(currentDir.canRead()));

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

    private boolean performPlayIntegrityCheck(final Context context, String verifyKey, String decryptKey) {
        final String nonce = NonceUtil.generateNonce(16);
        Log.i("Nonce", nonce);
        // but can be stored in a safer way, for example on a server
        // and obtained by a secure http request
        final String DECRYPTION_KEY = decryptKey;
        final String VERIFICATION_KEY = verifyKey;
        // Create an instance of IntegrityManager
        IntegrityManager integrityManager = IntegrityManagerFactory.create(context);

        // Request the integrity token by providing the nonce
        Task<IntegrityTokenResponse> integrityTokenResponse = integrityManager
                .requestIntegrityToken(IntegrityTokenRequest.builder().setNonce(nonce).build())
                .addOnSuccessListener(response -> {
                    String integrityToken = response.token();
                    Log.i(TAG, "Integrity Token: " + integrityToken);

                    byte[] decryptionKeyBytes = Base64.decode(DECRYPTION_KEY, Base64.DEFAULT);
                    SecretKey decryptionKey = new SecretKeySpec(decryptionKeyBytes, 0, decryptionKeyBytes.length, "AES");

                    byte[] encodedVerificationKey = Base64.decode(VERIFICATION_KEY, Base64.DEFAULT);
                    PublicKey verificationKey = null;

                    try {
                        verificationKey = KeyFactory.getInstance("EC")
                                .generatePublic(new X509EncodedKeySpec(encodedVerificationKey));
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                        Log.i(TAG, e.getMessage());
                    }

                    if (verificationKey == null) {
                        return;
                    }

                    JsonWebEncryption jwe = null;
                    try {
                        jwe = (JsonWebEncryption) JsonWebSignature.fromCompactSerialization(integrityToken);
                    } catch (JoseException e) {
                        e.printStackTrace();
                    }

                    if (jwe == null) {
                        return;
                    }

                    jwe.setKey(decryptionKey);

                    String compactJws = null;
                    try {
                        compactJws = jwe.getPayload();
                    } catch (JoseException e) {
                        Log.i(TAG, e.getMessage());
                    }

                    JsonWebSignature jws = null;
                    try {
                        jws = (JsonWebSignature) JsonWebSignature.fromCompactSerialization(compactJws);
                    } catch (JoseException e) {
                        Log.i(TAG, e.getMessage());
                    }

                    if (jws == null) {
                        return;
                    }

                    jws.setKey(verificationKey);

                    String jsonPlainVerdict = "";
                    try {
                        jsonPlainVerdict = jws.getPayload();
                    } catch (JoseException e) {
                        Log.i(TAG, e.getMessage());
                        return;
                    }

                    isJailbroken = parseDeviceIntegrity(jsonPlainVerdict);

                    Log.i(TAG, jsonPlainVerdict);
                })
                .addOnFailureListener(ex -> {
                    isJailbroken = true;
                    Log.i(TAG, "Error requesting integrity token: " + ex.getMessage());
                });

        return isJailbroken;
    }

    private CompletableFuture<Boolean> performPlayIntegrityCheckAsync(final Context context, String verifyKey, String decryptKey) {
        return CompletableFuture.supplyAsync(() -> {
            final String nonce = NonceUtil.generateNonce(16);
            String decKey = "";
            if (Objects.equals(decryptKey, "NoVerification")) {
                decKey = "nmzeD9LVp6yxJ3kvn3KETASozsqM+yx45G4NqKLeiFc=";
            } else {
                decKey = decryptKey;
            }

            String verKey ="";
            if (Objects.equals(verifyKey, "NoVerification")) {
                verKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOE63FZbxD8193Sz/KwlBfb5LYyBZSYOckuys17CuGp6KWgzju8xUmwy0gXpkSgNIZZxDTdD6mGMBnUOmwk0zSQ==";
            } else {
                verKey = verifyKey;
            }

            final String DECRYPTION_KEY = decKey;
            final String VERIFICATION_KEY = verKey;
            IntegrityManager integrityManager = IntegrityManagerFactory.create(context);

            Task<IntegrityTokenResponse> integrityTokenResponse = integrityManager
                    .requestIntegrityToken(IntegrityTokenRequest.builder().setNonce(nonce).build());

            try {
                IntegrityTokenResponse response = Tasks.await(integrityTokenResponse);
                String integrityToken = response.token();
                Log.i(TAG, "Integrity Token: " + integrityToken);

                byte[] decryptionKeyBytes = Base64.decode(DECRYPTION_KEY, Base64.DEFAULT);
                SecretKey decryptionKey = new SecretKeySpec(decryptionKeyBytes, 0, decryptionKeyBytes.length, "AES");

                byte[] encodedVerificationKey = Base64.decode(VERIFICATION_KEY, Base64.DEFAULT);
                PublicKey verificationKey = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(encodedVerificationKey));

                JsonWebEncryption jwe = (JsonWebEncryption) JsonWebSignature.fromCompactSerialization(integrityToken);
                jwe.setKey(decryptionKey);

                String compactJws = jwe.getPayload();

                JsonWebSignature jws = (JsonWebSignature) JsonWebSignature.fromCompactSerialization(compactJws);
                jws.setKey(verificationKey);

                String jsonPlainVerdict = jws.getPayload();
                isJailbroken = parseDeviceIntegrity(jsonPlainVerdict);

                Log.i(TAG, jsonPlainVerdict);
            } catch (Exception e) {
//               Its going in exception because google play integrity api might be blocked by some third pary service or internet access is not given in this case we will consider the app as jailbroken
                isJailbroken = false;
                Log.i(TAG, "Error requesting integrity token: " + e.getMessage());
            }

            return isJailbroken;
        });
    }

    private boolean parseDeviceIntegrity(String jsonString) {
        try {
            // Parse the JSON string into a JSONObject
            JSONObject jsonObject = new JSONObject(jsonString);

            // Get the deviceIntegrity object
            JSONObject deviceIntegrity = jsonObject.getJSONObject("deviceIntegrity");

            JSONArray deviceRecognitionVerdict;
            // Device recognistion will come in non rooted device if not coming then device might be rooted
            try {
                // Get the deviceRecognitionVerdict array
                deviceRecognitionVerdict = deviceIntegrity.getJSONArray("deviceRecognitionVerdict");
            } catch(JSONException error) {
                return true;
            }


            // Log the values for debugging
            for (int i = 0; i < deviceRecognitionVerdict.length(); i++) {
                String verdict = deviceRecognitionVerdict.getString(i);
                Log.d(TAG, "Verdict: " + verdict);
            }

            // Check if the required values are present
            boolean meetsCriteria = false;
            for (int i = 0; i < deviceRecognitionVerdict.length(); i++) {
                String verdict = deviceRecognitionVerdict.getString(i);
                if (verdict.equals("MEETS_BASIC_INTEGRITY") || 
                    verdict.equals("MEETS_DEVICE_INTEGRITY") || 
                    verdict.equals("MEETS_STRONG_INTEGRITY")) {
                    meetsCriteria = true;
                    break;
                }
            }

            if (meetsCriteria) {

                // The device meets the required integrity criteria
                Log.d(TAG, "Device meets the required integrity criteria.");
                return false;
            } else {
                // The device does not meet the required integrity criteria
                Log.d(TAG, "Device does not meet the required integrity criteria.");
                return true;
            }

        } catch (JSONException e) {
            Log.e(TAG, "JSON Exception: " + e.getMessage());
            e.printStackTrace();
        }
        return false;
    }

    private boolean checkNativeLibraryLoaded() {
            boolean libraryLoaded = false;
            try {
                System.loadLibrary("toolChecker");
                libraryLoaded = true;
            } catch (UnsatisfiedLinkError e) {

            }
            return libraryLoaded;

    }

    private boolean checkSuExists() {
        Process process = null;
        Log.i("checkSuExists", String.valueOf(process));
        try {
            Log.i("checkSuExists", String.valueOf(479));
            process = Runtime.getRuntime().exec("ls -lart");

            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            Log.i("checkSuExists", String.valueOf(in.readLine()));

            return in.readLine() != null;
        } catch (Throwable t) {
            Log.i("checkSuExists", String.valueOf(t));
            return false;
        } finally {
            if (process != null) process.destroy();
        }
    }

    public boolean checkForBinary(String filename) {

        String[] pathsArray = Const.getPaths();
        boolean result = false;

        for (String path : pathsArray) {
            String completePath = path + filename;
            File f = new File(path, filename);
            boolean fileExists = f.exists();
            if (fileExists) {
                result = true;
            }
        }

        return result;
    }

    private String[] propsReader() {
        try {
            InputStream inputstream = Runtime.getRuntime().exec("getprop").getInputStream();
            if (inputstream == null) return null;
            String propVal = new Scanner(inputstream).useDelimiter("\\A").next();
            return propVal.split("\n");
        } catch (IOException | NoSuchElementException e) {
            return null;
        }
    }

    private String[] mountReader() {
        try {
            InputStream inputstream = Runtime.getRuntime().exec("mount").getInputStream();
            if (inputstream == null) return null;
            String propVal = new Scanner(inputstream).useDelimiter("\\A").next();
            return propVal.split("\n");
        } catch (NoSuchElementException | IOException e) {
            return null;
        }
    }

    public boolean checkForDangerousProps() {

        final Map<String, String> dangerousProps = new HashMap<>();
        dangerousProps.put("ro.debuggable", "1");
        dangerousProps.put("ro.secure", "0");

        boolean result = false;

        String[] lines = propsReader();

        if (lines == null){
            // Could not read, assume false;
            return false;
        }

        for (String line : lines) {
            for (String key : dangerousProps.keySet()) {
                if (line.contains(key)) {
                    String badValue = dangerousProps.get(key);
                    badValue = "[" + badValue + "]";
                    if (line.contains(badValue)) {
                        result = true;
                    }
                }
            }
        }
        return result;
    }

    /**
     * When you're root you can change the permissions on common system directories, this method checks if any of these patha Const.pathsThatShouldNotBeWritable are writable.
     * @return true if one of the dir is writable
     */
    public boolean checkForRWPaths() {

        boolean result = false;

        //Run the command "mount" to retrieve all mounted directories
        String[] lines = mountReader();

        if (lines == null){
            // Could not read, assume false;
            return false;
        }

        //The SDK version of the software currently running on this hardware device.
        int sdkVersion = android.os.Build.VERSION.SDK_INT;
        Log.i("sdkVersion", String.valueOf(sdkVersion));

        for (String line : lines) {

            // Split lines into parts
            String[] args = line.split(" ");

            if ((sdkVersion <= android.os.Build.VERSION_CODES.M && args.length < 4)
                    || (sdkVersion > android.os.Build.VERSION_CODES.M && args.length < 6)) {
                // If we don't have enough options per line, skip this and log an error
                continue;
            }

            String mountPoint;
            String mountOptions;

            /**
             * To check if the device is running Android version higher than Marshmallow or not
             */
            if (sdkVersion > android.os.Build.VERSION_CODES.M) {
                mountPoint = args[2];
                mountOptions = args[5];
            } else {
                mountPoint = args[1];
                mountOptions = args[3];
            }

            for(String pathToCheck: Const.pathsThatShouldNotBeWritable) {
                if (mountPoint.equalsIgnoreCase(pathToCheck)) {

                    /**
                     * If the device is running an Android version above Marshmallow,
                     * need to remove parentheses from options parameter;
                     */
                    if (android.os.Build.VERSION.SDK_INT > android.os.Build.VERSION_CODES.M) {
                        mountOptions = mountOptions.replace("(", "");
                        mountOptions = mountOptions.replace(")", "");

                    }

                    // Split options out and compare against "rw" to avoid false positives
                    for (String option : mountOptions.split(",")){

                        if (option.equalsIgnoreCase("rw")){
                            result = true;
                            break;
                        }
                    }
                }
            }
        }

        return result;
    }

    private boolean checkForMagiskBinary(){ return checkForBinary("magisk"); }



}
