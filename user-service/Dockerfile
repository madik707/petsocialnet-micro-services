# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

COPY user-service/pom.xml user-service/
RUN mvn -f user-service/pom.xml dependency:go-offline

COPY user-service /build/user-service
RUN mvn -f user-service/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app
COPY --from=builder /build/user-service/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
