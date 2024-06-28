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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import android.util.Base64;
import androidx.appcompat.app.AppCompatActivity;


public class JailbreakRootDetection extends AppCompatActivity {

    private static final String TAG = "JailbreakRootDetection";
    private boolean isJailbroken = false;
    public String echo(String value) {
        Log.i("Echo", value);
        return value;
    }

    public Boolean jailbroken(Context context, String verificationKey, String decryptionKey) {
        Log.i("JailbreakRootDetection", "Checking root detectection");
        boolean isJailbroken =
                checkRootMethod1() ||
                checkRootMethod2() ||
                checkRootMethod3() ||
                checkRootBypassApps(context) ||
                checkDirPermissions() ||
                checkforOverTheAirCertificates();
         CompletableFuture<Boolean> future = performPlayIntegrityCheckAsync(context, verificationKey, decryptionKey);
         //  Apply the device integrity test then send the result to the app
         try {
             isJailbroken = future.get(); // This will block until the future completes
             Log.i(TAG, "Is device jailbroken: " + isJailbroken);
         } catch (InterruptedException | ExecutionException e) {
             Log.i(TAG, "An error occurred: " + e.getMessage());
         }
        Log.i("JailbreakRootDetection", "Jailbreak Detection Completed");
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
                "/su/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/system/bin/busybox",
                "/system/xbin/busybox",
                "/system/xbin/daemonsu",
                "/system/sd/xbin/su",
                "/system/usr/we-need-root/su-backup"
        };
        for (String path : paths) {
            Log.i("checkRootMethod1", path);
            boolean checkPath = new File(path).exists();
            Log.i("checkPath", new String(String.valueOf(checkPath)));
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
                Log.i("executeCommands", command);
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

    private boolean isAnyPackageInstalled(List<String> packages, final Context context) {
        PackageManager pm = context.getPackageManager();
        for (String packageName : packages) {
            try {
                Log.i("Package Name", packageName);
                PackageInfo isPackageInstalled = pm.getPackageInfo(packageName, 0);
                Log.i("isPackageInstalled", String.valueOf(isPackageInstalled));
                return true;  // Package found
            } catch (PackageManager.NameNotFoundException e) {
                Log.i("Package Name Not Found", packageName);
                // Package not found
            }
        }
        Log.i("Returning false", "Check Failed");
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

            isWritableDir = currentDir.exists() && currentDir.canWrite();
            isReadableDataDir = (dirName.equals("/data") && currentDir.canRead());

            Log.i("checkDirPermissions isWritableDir", String.valueOf(isWritableDir));
            Log.i("checkDirPermissions isReadableDataDir", String.valueOf(isReadableDataDir));

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
        // DECRYPTION_KEY, VERIFICATION_KEY are hard-coded for tutorial
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
            Log.i("Nonce", nonce);

            final String DECRYPTION_KEY = decryptKey;
            final String VERIFICATION_KEY = verifyKey;
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


}
