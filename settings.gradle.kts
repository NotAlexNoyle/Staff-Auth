rootProject.name="Staff-Auth"

pluginManagement {
    val kotlinVersion = providers.gradleProperty("kotlinVersion")
    plugins {
        kotlin("jvm") version kotlinVersion
        kotlin("plugin.allopen") version kotlinVersion
    }
}