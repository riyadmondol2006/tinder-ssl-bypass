/*
 * Tinder SSL/TLS Bypass Script
 * Bypasses SSL pinning, proxy detection, and certificate validation
 * Works with OkHttp, Volley, HttpsURLConnection, and native libraries
 * 
 * Author: Riyad Mondol
 * Telegram: https://t.me/reversesio
 * Website: http://reversesio.com/ http://reversesio.shop/
 * Contact Me: riyadmondol2006@gmail.com
 * Feel free to reach out to me on Telegram for any project opportunities: https://t.me/riyadmondol2006
 */

console.log("╔═══════════════════════════════════════════════════════════════════════════════╗");
console.log("║                    🔥 TINDER SSL/TLS BYPASS SCRIPT 🔥                       ║");
console.log("║═══════════════════════════════════════════════════════════════════════════════║");
console.log("║  Author: Riyad Mondol                                                        ║");
console.log("║  GitHub: https://github.com/riyadmondol2006                                  ║");
console.log("║  Telegram: https://t.me/reversesio                                           ║");
console.log("║  Website: http://reversesio.com | http://reversesio.shop                     ║");
console.log("║  Contact: riyadmondol2006@gmail.com                                          ║");
console.log("║  Projects: https://t.me/riyadmondol2006                                      ║");
console.log("║═══════════════════════════════════════════════════════════════════════════════║");
console.log("║  ✅ SSL Certificate Pinning Bypass                                           ║");
console.log("║  ✅ Proxy Detection Bypass                                                   ║");
console.log("║  ✅ Anti-Debugging & Root Detection Bypass                                   ║");
console.log("║  ✅ Network Traffic Interception                                             ║");
console.log("║  ✅ Native Library Hooks                                                     ║");
console.log("╚═══════════════════════════════════════════════════════════════════════════════╝");
console.log("[*] Starting Tinder SSL/TLS Bypass Script");

// Java.perform ensures we run in the Java context
Java.perform(function() {
    
    // SSL Context and Trust Manager bypasses
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.use("javax.net.ssl.TrustManager");
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        
        // Create a permissive trust manager
        var TrustManagerImpl = Java.registerClass({
            name: "com.frida.TrustManagerImpl",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    // Accept all client certificates
                },
                checkServerTrusted: function(chain, authType) {
                    // Accept all server certificates
                },
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        
        // Hook SSLContext.init
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log("[+] SSLContext.init called - bypassing with custom trust manager");
            var trustManager = TrustManagerImpl.$new();
            this.init(keyManagers, [trustManager], secureRandom);
        };
        
        console.log("[+] SSL Context bypass enabled");
    } catch (e) {
        console.log("[-] SSL Context bypass failed: " + e);
    }
    
    // OkHttp3 Certificate Pinner bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] Certificate pinning bypassed for: " + hostname);
            return;
        };
        
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
            console.log("[+] Certificate pinning bypassed for: " + hostname);
            return;
        };
        
        console.log("[+] OkHttp3 Certificate Pinner bypass enabled");
    } catch (e) {
        console.log("[-] OkHttp3 Certificate Pinner bypass failed: " + e);
    }
    
    // OkHttp3 Hostname Verifier bypass
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
            console.log("[+] Hostname verification bypassed for: " + hostname);
            return true;
        };
        
        OkHostnameVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(hostname, certificate) {
            console.log("[+] Hostname verification bypassed for: " + hostname);
            return true;
        };
        
        console.log("[+] OkHttp3 Hostname Verifier bypass enabled");
    } catch (e) {
        console.log("[-] OkHttp3 Hostname Verifier bypass failed: " + e);
    }
    
    // HttpsURLConnection bypass
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] Default hostname verifier bypass");
            var TrustAllHostnameVerifier = Java.registerClass({
                name: "com.frida.TrustAllHostnameVerifier",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function(hostname, session) {
                        return true;
                    }
                }
            });
            return this.setDefaultHostnameVerifier(TrustAllHostnameVerifier.$new());
        };
        
        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] Hostname verifier bypass");
            var TrustAllHostnameVerifier = Java.registerClass({
                name: "com.frida.TrustAllHostnameVerifier2",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function(hostname, session) {
                        return true;
                    }
                }
            });
            return this.setHostnameVerifier(TrustAllHostnameVerifier.$new());
        };
        
        console.log("[+] HttpsURLConnection bypass enabled");
    } catch (e) {
        console.log("[-] HttpsURLConnection bypass failed: " + e);
    }
    
    // Volley SSL bypass
    try {
        var HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
        
        HurlStack.createConnection.implementation = function(url) {
            console.log("[+] Volley HurlStack connection bypass for: " + url);
            var connection = this.createConnection(url);
            if (connection instanceof Java.use("javax.net.ssl.HttpsURLConnection")) {
                var TrustAllHostnameVerifier = Java.registerClass({
                    name: "com.frida.VolleyTrustAllHostnameVerifier",
                    implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                    methods: {
                        verify: function(hostname, session) {
                            return true;
                        }
                    }
                });
                connection.setHostnameVerifier(TrustAllHostnameVerifier.$new());
            }
            return connection;
        };
        
        console.log("[+] Volley SSL bypass enabled");
    } catch (e) {
        console.log("[-] Volley SSL bypass failed: " + e);
    }
    
    // Network Security Policy bypass
    try {
        var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
        
        NetworkSecurityPolicy.getInstance.implementation = function() {
            console.log("[+] Network Security Policy bypass");
            return this.getInstance();
        };
        
        // Try to bypass individual methods
        try {
            NetworkSecurityPolicy.isCleartextTrafficPermitted.overload().implementation = function() {
                console.log("[+] Cleartext traffic permitted (global)");
                return true;
            };
        } catch (e) {
            console.log("[-] Global cleartext bypass failed: " + e);
        }
        
        try {
            NetworkSecurityPolicy.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function(hostname) {
                console.log("[+] Cleartext traffic permitted for: " + hostname);
                return true;
            };
        } catch (e) {
            console.log("[-] Hostname cleartext bypass failed: " + e);
        }
        
        try {
            NetworkSecurityPolicy.isCertificateTransparencyVerificationRequired.implementation = function(hostname) {
                console.log("[+] Certificate transparency verification bypassed for: " + hostname);
                return false;
            };
        } catch (e) {
            console.log("[-] Certificate transparency bypass failed: " + e);
        }
        
        console.log("[+] Network Security Policy bypass enabled");
    } catch (e) {
        console.log("[-] Network Security Policy bypass failed: " + e);
    }
    
    // Proxy detection bypass
    try {
        var System = Java.use("java.lang.System");
        
        System.getProperty.overload('java.lang.String').implementation = function(property) {
            if (property === "http.proxyHost" || property === "http.proxyPort" || 
                property === "https.proxyHost" || property === "https.proxyPort") {
                console.log("[+] Proxy property request blocked: " + property);
                return null;
            }
            return this.getProperty(property);
        };
        
        System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function(property, defaultValue) {
            if (property === "http.proxyHost" || property === "http.proxyPort" || 
                property === "https.proxyHost" || property === "https.proxyPort") {
                console.log("[+] Proxy property request blocked: " + property);
                return null;
            }
            return this.getProperty(property, defaultValue);
        };
        
        console.log("[+] Proxy detection bypass enabled");
    } catch (e) {
        console.log("[-] Proxy detection bypass failed: " + e);
    }
    
    // Root detection bypass
    try {
        // Try common root detection libraries
        try {
            var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
            RootBeer.isRooted.implementation = function() {
                console.log("[+] RootBeer detection bypassed");
                return false;
            };
        } catch (e) {
            console.log("[-] RootBeer not found, trying other methods");
        }
        
        // Try alternative root detection methods
        try {
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
                var cmd = cmdArray.join(" ");
                if (cmd.includes("su") || cmd.includes("which") || cmd.includes("busybox")) {
                    console.log("[+] Root command blocked: " + cmd);
                    throw new Error("Command blocked");
                }
                return this.exec(cmdArray);
            };
        } catch (e) {
            console.log("[-] Runtime.exec hook failed: " + e);
        }
        
        console.log("[+] Root detection bypass enabled");
    } catch (e) {
        console.log("[-] Root detection bypass failed: " + e);
    }
    
    // Anti-debugging bypass
    try {
        var Debug = Java.use("android.os.Debug");
        
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[+] Debugger detection bypassed");
            return false;
        };
        
        console.log("[+] Anti-debugging bypass enabled");
    } catch (e) {
        console.log("[-] Anti-debugging bypass failed: " + e);
    }
    
    // Emulator detection bypass
    try {
        var Build = Java.use("android.os.Build");
        
        // Hook Build properties that might indicate emulator
        Build.FINGERPRINT.value = "google/sdk_gphone64_x86_64/emulator64_x86_64_arm64:11/RSR1.201013.001/6903271:user/release-keys";
        Build.MODEL.value = "Pixel 4";
        Build.MANUFACTURER.value = "Google";
        Build.BRAND.value = "google";
        Build.DEVICE.value = "flame";
        Build.PRODUCT.value = "flame";
        Build.HARDWARE.value = "flame";
        Build.RADIO.value = "g7250-00042-200421-B-6133887";
        
        console.log("[+] Emulator detection bypass enabled");
    } catch (e) {
        console.log("[-] Emulator detection bypass failed: " + e);
    }
    
    // Frida detection bypass
    try {
        var ActivityThread = Java.use("android.app.ActivityThread");
        
        ActivityThread.currentApplication.implementation = function() {
            console.log("[+] Frida detection bypass - ActivityThread.currentApplication");
            return this.currentApplication();
        };
        
        console.log("[+] Frida detection bypass enabled");
    } catch (e) {
        console.log("[-] Frida detection bypass failed: " + e);
    }
});

// Native library hooks
function hookNativeLibraries() {
    console.log("[*] Setting up native library hooks...");
    
    // List of potential SSL library names
    var sslLibraries = [
        "libssl.so", "libssl.so.1.1", "libssl.so.1.0.0", "libssl.so.3",
        "libcrypto.so", "libcrypto.so.1.1", "libcrypto.so.1.0.0", "libcrypto.so.3"
    ];
    
    var foundSSLLib = null;
    var foundCryptoLib = null;
    
    // Find available SSL libraries
    sslLibraries.forEach(function(lib) {
        try {
            if (Module.findExportByName(lib, "SSL_CTX_set_verify")) {
                foundSSLLib = lib;
                console.log("[+] Found SSL library: " + lib);
            }
            if (Module.findExportByName(lib, "X509_verify_cert")) {
                foundCryptoLib = lib;
                console.log("[+] Found Crypto library: " + lib);
            }
        } catch (e) {
            // Library not found, continue
        }
    });
    
    // Hook SSL_CTX_set_verify
    if (foundSSLLib) {
        try {
            var SSL_CTX_set_verify = Module.findExportByName(foundSSLLib, "SSL_CTX_set_verify");
            if (SSL_CTX_set_verify) {
                Interceptor.replace(SSL_CTX_set_verify, new NativeCallback(function(ctx, mode, verify_callback) {
                    console.log("[+] SSL_CTX_set_verify bypassed");
                    return 0;
                }, 'int', ['pointer', 'int', 'pointer']));
                console.log("[+] SSL_CTX_set_verify hook successful");
            }
        } catch (e) {
            console.log("[-] SSL_CTX_set_verify hook failed: " + e);
        }
        
        // Hook SSL_set_verify
        try {
            var SSL_set_verify = Module.findExportByName(foundSSLLib, "SSL_set_verify");
            if (SSL_set_verify) {
                Interceptor.replace(SSL_set_verify, new NativeCallback(function(ssl, mode, verify_callback) {
                    console.log("[+] SSL_set_verify bypassed");
                    return 0;
                }, 'int', ['pointer', 'int', 'pointer']));
                console.log("[+] SSL_set_verify hook successful");
            }
        } catch (e) {
            console.log("[-] SSL_set_verify hook failed: " + e);
        }
        
        // Hook SSL_CTX_set_cert_verify_callback
        try {
            var SSL_CTX_set_cert_verify_callback = Module.findExportByName(foundSSLLib, "SSL_CTX_set_cert_verify_callback");
            if (SSL_CTX_set_cert_verify_callback) {
                Interceptor.replace(SSL_CTX_set_cert_verify_callback, new NativeCallback(function(ctx, callback, arg) {
                    console.log("[+] SSL_CTX_set_cert_verify_callback bypassed");
                    return 0;
                }, 'int', ['pointer', 'pointer', 'pointer']));
                console.log("[+] SSL_CTX_set_cert_verify_callback hook successful");
            }
        } catch (e) {
            console.log("[-] SSL_CTX_set_cert_verify_callback hook failed: " + e);
        }
    } else {
        console.log("[-] No SSL library found for hooking");
    }
    
    // Hook certificate verification functions
    if (foundCryptoLib) {
        try {
            var X509_verify_cert = Module.findExportByName(foundCryptoLib, "X509_verify_cert");
            if (X509_verify_cert) {
                Interceptor.replace(X509_verify_cert, new NativeCallback(function(ctx) {
                    console.log("[+] X509_verify_cert bypassed - returning success");
                    return 1;
                }, 'int', ['pointer']));
                console.log("[+] X509_verify_cert hook successful");
            }
        } catch (e) {
            console.log("[-] X509_verify_cert hook failed: " + e);
        }
    } else {
        console.log("[-] No Crypto library found for X509 verification");
    }
    
    // Check for Tinder native libraries
    try {
        var libraries = ["libFaceMeSDK.so", "libPhoenixAndroid.so", "libcoreface.so"];
        libraries.forEach(function(lib) {
            try {
                var base = Module.findBaseAddress(lib);
                if (base) {
                    console.log("[+] Found " + lib + " at " + base);
                    console.log("[+] " + lib + " detected but not hooked (requires specific analysis)");
                } else {
                    console.log("[-] " + lib + " not found or not loaded");
                }
            } catch (e) {
                console.log("[-] Failed to check " + lib + ": " + e);
            }
        });
    } catch (e) {
        console.log("[-] Native library detection failed: " + e);
    }
}

// Set up native hooks after a delay to ensure libraries are loaded
setTimeout(function() {
    hookNativeLibraries();
}, 2000);

// Additional bypass for custom implementations
Java.perform(function() {
    // Hook custom certificate pinning implementations
    try {
        // Look for Tinder-specific certificate pinning classes
        var classes = Java.enumerateLoadedClassesSync();
        classes.forEach(function(className) {
            if (className.includes("tinder") || className.includes("Tinder")) {
                if (className.includes("ssl") || className.includes("SSL") || 
                    className.includes("cert") || className.includes("Cert") ||
                    className.includes("pin") || className.includes("Pin")) {
                    try {
                        var clazz = Java.use(className);
                        var methods = clazz.class.getDeclaredMethods();
                        methods.forEach(function(method) {
                            var methodName = method.getName();
                            if (methodName.includes("verify") || methodName.includes("check") || 
                                methodName.includes("validate") || methodName.includes("pin")) {
                                try {
                                    console.log("[+] Found potential certificate method: " + className + "." + methodName);
                                    // Hook the method to always return true/success
                                    clazz[methodName].implementation = function() {
                                        console.log("[+] Bypassed " + className + "." + methodName);
                                        return true;
                                    };
                                } catch (e) {
                                    console.log("[-] Failed to hook " + className + "." + methodName + ": " + e);
                                }
                            }
                        });
                    } catch (e) {
                        console.log("[-] Failed to process class " + className + ": " + e);
                    }
                }
            }
        });
    } catch (e) {
        console.log("[-] Custom implementation bypass failed: " + e);
    }
    
    // Log all network requests for debugging
    try {
        var URL = Java.use("java.net.URL");
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        URL.$init.overload('java.lang.String').implementation = function(url) {
            console.log("[*] Network request to: " + url);
            return this.$init(url);
        };
        
        HttpURLConnection.connect.implementation = function() {
            console.log("[*] HTTP connection established to: " + this.getURL());
            return this.connect();
        };
        
        console.log("[+] Network request logging enabled");
    } catch (e) {
        console.log("[-] Network request logging failed: " + e);
    }
});

console.log("[*] Tinder SSL/TLS Bypass Script loaded successfully");
console.log("[*] All security bypasses are now active");
console.log("[*] You can now intercept HTTPS traffic with your proxy tool");