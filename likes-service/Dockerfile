# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

COPY likes-service/pom.xml likes-service/
RUN mvn -f likes-service/pom.xml dependency:go-offline

COPY likes-service /build/likes-service
RUN mvn -f likes-service/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app
COPY --from=builder /build/likes-service/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
