val accpVersion = "2.3.1"
val accpLocalJar: String by project
val fips: Boolean by project

plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.6.21"
    id("com.google.osdetector") version "1.7.0"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    // Use the Kotlin JDK 8 standard library.
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")

    val accpArtifactId =
        if (project.hasProperty("fips"))
            "AmazonCorrettoCryptoProvider-FIPS"
        else
            "AmazonCorrettoCryptoProvider"

    if (project.hasProperty("accpLocalJar")) {
        testImplementation(files(accpLocalJar))
    } else {
        testImplementation("software.amazon.cryptools:${accpArtifactId}:$accpVersion:${osdetector.classifier}")
    }

    testImplementation("com.amazonaws:aws-encryption-sdk-java:2.4.0")
}

tasks.withType<Test> {
    systemProperties(System.getProperties().toMap() as Map<String, Object>)
    this.testLogging {
        this.showStandardStreams = true
    }
}
