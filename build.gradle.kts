plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    id("com.gradleup.shadow") version "8.3.5"
}

group = "webrtc.testsuite"
version = "1.0.5"

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime -> compileOnly, never bundled.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")

    // Bundled into the fat jar (not on Burp's classpath).
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test-junit"))
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.7")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    // Reproduce a runtime without the optional jdk.httpserver module.
    jvmArgs("--limit-modules=java.se,jdk.unsupported")
}

tasks.processResources {
    from("agent/webrtc-agent.js") { into("agent") }
    from("runner/tls_runner.py") { into("runner") }
    val buildVersion = project.version.toString()
    inputs.property("version", buildVersion)
    filesMatching("webrtc-version.properties") { expand("version" to buildVersion) }
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "WebRTC Test Suite",
            "Implementation-Version" to project.version.toString()
        )
    }
}

tasks.shadowJar {
    archiveBaseName.set("webrtc-testsuite")
    archiveClassifier.set("all")
    archiveVersion.set("")
    mergeServiceFiles()
    manifest {
        attributes(
            "Implementation-Title" to "WebRTC Test Suite",
            "Implementation-Version" to project.version.toString()
        )
    }
}

// Make `build` produce the extension jar.
tasks.build {
    dependsOn(tasks.shadowJar)
}
