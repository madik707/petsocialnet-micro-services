# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

COPY friends-service/pom.xml friends-service/
RUN mvn -f friends-service/pom.xml dependency:go-offline

COPY friends-service /build/friends-service
RUN mvn -f friends-service/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app
COPY --from=builder /build/friends-service/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
