// Krypto-Kern der europe.social-App für Android: reines Kotlin (JVM), Tests laufen auf der JVM.
plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
}


dependencies {
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    testImplementation(kotlin("test"))
    testImplementation(platform("org.junit:junit-bom:5.12.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("europe.repoRoot", rootProject.projectDir.parentFile.absolutePath)
}
