val accpVersion: String? by project
val accpLocalJar: String by project
val fips: Boolean by project
val includeBenchmark: String by project
val jostleVersion: String? by project
val nativeContextReleaseStrategy: String by project

plugins {
    `java-library`
    id("me.champeau.jmh") version "0.7.1"
    id("io.morethan.jmhreport") version "0.9.0"
    id("com.google.osdetector") version "1.7.0"
}

repositories {
    mavenCentral()
}

dependencies {
    jmh("org.projectlombok:lombok:1.18.28")
    jmh("org.bouncycastle:bcprov-jdk18on:1.81")

    // openssl-jostle is POM-packaged with no classifier-less jar, so the architecture
    // classifier is mandatory. It does not use osdetector's naming for aarch64.
    val jostleClassifier = when (val arch = osdetector.arch) {
        "x86_64" -> "x86_64"
        "aarch_64" -> "aarch64"
        else -> throw GradleException("openssl-jostle publishes no artifact for $arch")
    }
    val publishedJostleVersion = if (project.hasProperty("jostleVersion")) jostleVersion else "0.1.0"
    jmh("org.openssl.jostle:openssl-jostle:$publishedJostleVersion:$jostleClassifier")

    val accpArtifactId =
    if (project.hasProperty("fips"))
        "AmazonCorrettoCryptoProvider-FIPS"
    else
        "AmazonCorrettoCryptoProvider"

    val publishedAccpVersion =
    if (project.hasProperty("accpVersion"))
        accpVersion
    else
        "2.+"


    if (!project.hasProperty("useBundledAccp")) {
        if (project.hasProperty("accpLocalJar")) {
            jmh(files(accpLocalJar))
        } else {
            jmh("software.amazon.cryptools:${accpArtifactId}:$publishedAccpVersion:${osdetector.classifier}")
        }
    }

}

jmh {
    if (project.hasProperty("includeBenchmark")) {
        includes.add(includeBenchmark)
    }
    fork.set(1)
    // Do not specify benchmarkMode nor timeUnit to allow each benchmark to use their own
    // Do not set threads.set(1) as it prevents multi-threaded benchmarks
    // Classes without any annotation will use a single thread and ops/s by default
    iterations.set(5)
    timeOnIteration.set("3s")
    warmup.set("1s")
    warmupIterations.set(3)
    resultFormat.set("JSON")
    duplicateClassesStrategy.set(DuplicatesStrategy.WARN)
    jvmArgs.add("-DversionStr=${accpVersion}")
    // Jostle calls System.load, which JDK 24 onwards warns about. JDK 11 rejects the flag outright.
    if (JavaVersion.current() >= JavaVersion.VERSION_24) {
        jvmArgs.add("--enable-native-access=ALL-UNNAMED")
    }
    if (project.hasProperty("nativeContextReleaseStrategy")) {
        jvmArgs.add("-Dcom.amazon.corretto.crypto.provider.nativeContextReleaseStrategy=${nativeContextReleaseStrategy}")
    }
}

jmhReport {
    jmhReportOutput = "lib/build/results/jmh"
    jmhResultPath = "${jmhReportOutput}/results.json"
}

tasks.jmh {
    finalizedBy(tasks.jmhReport)
}
