val accpVersion: String? by project
val accpLocalJar: String by project
val fips: Boolean by project
val includeBenchmark: String by project
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
    jmh("org.bouncycastle:bcprov-jdk15on:1.70")

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
    benchmarkMode.add("thrpt")
    threads.set(1)
    timeUnit.set("s")
    iterations.set(5)
    timeOnIteration.set("3s")
    warmup.set("1s")
    warmupIterations.set(3)
    resultFormat.set("JSON")
    duplicateClassesStrategy.set(DuplicatesStrategy.WARN)
    jvmArgs.add("-DversionStr=${accpVersion}")
    jvmArgs.add("-Dcom.amazon.corretto.crypto.provider.registerSecureRandom=true")
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
