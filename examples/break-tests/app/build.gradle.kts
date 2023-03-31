plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("../../../build/cmake/AmazonCorrettoCryptoProvider.jar"))
}

application {
    // Define the main class for the application.
    mainClass.set("com.amazon.accp.breaktests.App")
}

tasks.withType<Jar> {
    manifest {
        attributes["Main-Class"] = "com.amazon.accp.breaktests.App"
    }
}

tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}
