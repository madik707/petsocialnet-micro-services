# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

COPY github-config-server/pom.xml github-config-server/
RUN mvn -f github-config-server/pom.xml dependency:go-offline

COPY github-config-server /build/github-config-server
RUN mvn -f github-config-server/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app
COPY --from=builder /build/github-config-server/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
