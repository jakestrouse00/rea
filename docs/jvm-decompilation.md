# JVM decompilation (Vineflower)

Two tools decompile **caller-held** JVM classes through a caller-supplied
[Vineflower](https://github.com/Vineflower/vineflower) JAR and a JDK. REA never
downloads Vineflower or Java and never runs the decompiled classes.

| Tool                    | Scope                                             |
| ----------------------- | ------------------------------------------------- |
| `decompile_jar_class`   | One selected class from a JAR or class container. |
| `decompile_jar_archive` | Every class in a JAR, WAR, or class directory.    |

## Configuration

| Setting              | Meaning                                                      |
| -------------------- | ------------------------------------------------------------ |
| `REA_VINEFLOWER_JAR` | **Required.** Absolute path to the caller's Vineflower JAR.  |
| `JAVA_HOME`          | Optional absolute JDK home; `PATH` `java` is used otherwise. |

The provider asserts the JAR is readable and runs `java -version`, refusing a
runtime older than Java 11. A missing JAR or JDK is a typed configuration
refusal with the exact remediation. Decompilation writes `.java` sources into a
private, owner-only runtime directory that REA removes after the operation; a
failed removal is reported as incomplete cleanup with the retained path.

## What reaches Evidence

The result reports the container path, size, SHA-256, the selected JAR and Java
version, and each class's binary name, package, kind, and bounded member
signatures. A covered/unparsed line count and a truncation flag make partial
parses visible.

Recovered Java source never reaches Evidence. Output is not guaranteed to be
valid or faithful to the original source.

The Vineflower CLI and Java source shapes are documented assumptions; no
verified Vineflower release is pinned yet, and every result carries that note.
