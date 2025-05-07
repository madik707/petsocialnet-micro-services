# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

COPY post-service/pom.xml post-service/
RUN mvn -f post-service/pom.xml dependency:go-offline

COPY post-service /build/post-service
RUN mvn -f post-service/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app
COPY --from=builder /build/post-service/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
