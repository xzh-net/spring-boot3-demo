# Gradle 构建工具集成示例

Gradle是一个自动化的构建工具，它基于Apache Ant和Apache Maven的概念，但提供了更为灵活和强大的功能。与Maven相比，Gradle使用了一种基于Groovy的特定领域语言（DSL）来声明项目设置，这使得构建脚本更为简洁和易读。同时，Gradle也支持基于Kotlin语言的Kotlin DSL，从而提供了更多的选择



## Gradle的主要特点和优势

- 灵活性：Gradle允许你使用任何你喜欢的构建脚本语言，并提供了强大的自定义任务类型的功能。
- 性能：Gradle具有出色的构建性能，特别是对于那些大型项目。它支持构建缓存、守护进程和并行执行等特性，这些都有助于提高构建速度。
- 依赖管理：Gradle提供了强大的依赖管理功能，可以很容易地解决依赖冲突和版本问题。
- 多项目构建：Gradle可以轻松地管理多个相关的项目，使得构建过程更为高效。
- 插件系统：Gradle的插件系统允许你轻松地扩展构建过程的功能，以适应不同的项目需求。



## 为什么Spring Boot 3默认Gradle

- 简洁性：与Maven的XML配置文件相比，Gradle的构建脚本更为简洁和易读。这有助于减少维护的复杂性和提高开发效率。
- 灵活性：Gradle提供了更高的灵活性，允许开发者根据需要自定义构建过程。这对于需要复杂构建逻辑的项目来说是非常有价值的。
- 对新技术的支持：Gradle更快地支持新的Java版本和其他新技术。而Maven虽然稳定，但有时对新技术的支持可能会滞后。
- 性能优势：由于Gradle支持构建缓存、守护进程和并行执行等特性，它在某些情况下可能比Maven具有更好的构建性能。
- 需要注意的是，虽然Spring Boot推荐使用Gradle进行构建，但仍然支持使用Maven。开发者可以根据自己的喜好和项目需求选择合适的构建工具



## Gradle工程结构

```lua
├─src
│   ├─main
│   └─test
├─test
│   ├─main
│   └─test 
│ build.gradle 或 build.gradle.kts              //Gradle构建脚本文件，定义项目的构建逻辑、配置、依赖关系等。
│ settings.gradle 或 settings.gradle.kts        //Gradle设置文件，定义项目的根目录、子项目等。
│ gradle.properties                             //Gradle属性文件，配置构建过程中的属性，如JVM参数、项目版本等。
│ gradlew 和 gradlew.bat                        //Gradle Wrapper脚本文件，用于确保团队成员使用相同版本的Gradle。
│ gradle/wrapper/gradle-wrapper.properties      //Gradle Wrapper配置文件，指定Gradle版本和下载地址。
```

```bash
gradle clean
gradle build
```

