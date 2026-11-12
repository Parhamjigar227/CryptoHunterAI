plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.duolink.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.duolink.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 5
        versionName = "0.5.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Which signaling server the APK talks to by default.
    //
    // The value is NOT a secret - it is a public URL every client must know - so compiling it in is
    // correct and keeps the first-run experience to zero typing. Override per build without editing
    // this file:
    //     ./gradlew assembleDebug -Pduolink.signalingEndpoint=https://my-relay.example.com
    // or put `duolink.signalingEndpoint=https://my-relay.example.com` in `local.properties` (git-ignored).
    //
    // Deliberately left empty by default. An empty value makes the app ask the user for an address
    // instead of attempting a request to a placeholder such as `relay.duolink.invalid`, which is a
    // reserved TLD that never resolves and produced a misleading "network error" in 0.4.0.
    val signalingEndpoint: String =
        providers.gradleProperty("duolink.signalingEndpoint").getOrElse("")

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            buildConfigField("String", "DEFAULT_SIGNALING_ENDPOINT", "\"$signalingEndpoint\"")
        }
        debug {
            // Debug builds may also point at a loopback server, which the endpoint policy permits.
            val debugDefault = signalingEndpoint.ifEmpty { "http://127.0.0.1:8787" }
            buildConfigField("String", "DEFAULT_SIGNALING_ENDPOINT", "\"$debugDefault\"")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        // Required by the remote-pairing endpoint policy: `SignalingEndpointPolicy` accepts plain http://
        // ONLY for loopback addresses AND only in debug builds, and the caller passes
        // `BuildConfig.DEBUG` explicitly so the rule is enforced by code rather than by convention.
        // Without this flag BuildConfig is not generated and the release build would have no way to
        // tell itself apart from a debug build.
        buildConfig = true
    }

    testOptions {
        unitTests.all {
            it.testLogging {
                events("passed", "skipped", "failed")
            }
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    // BiometricPrompt + BiometricManager. Required by the app-lock gate (strong biometrics only).
    // Pulls in androidx.fragment; MainActivity therefore extends FragmentActivity so the prompt has
    // a FragmentManager to attach to.
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    // Activity Result API contract for the system photo/video picker (image + video sharing).
    implementation("androidx.activity:activity-ktx:1.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("io.coil-kt:coil-compose:2.7.0")

    // Milestone 2 offline QR encoding/decoding & camera frame analysis
    implementation("com.google.zxing:core:3.5.4")
    implementation("androidx.camera:camera-core:1.4.2")
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")

    // JVM unit tests
    testImplementation("junit:junit:4.13.2")
    testImplementation(kotlin("test"))

    // Android hardware Keystore, CameraX/ZXing & persistence instrumentation tests
    androidTestImplementation("androidx.test:core-ktx:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit-ktx:1.2.1")
    androidTestImplementation(kotlin("test"))

    debugImplementation("androidx.compose.ui:ui-tooling")
}
