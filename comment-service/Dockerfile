# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

# Копируем pom.xml и зависимости отдельно для кеширования
COPY comment-service/pom.xml comment-service/
RUN mvn -f comment-service/pom.xml dependency:go-offline

# Копируем исходники и собираем
COPY comment-service /build/comment-service
RUN mvn -f comment-service/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app

# Копируем собранный JAR из предыдущего этапа
COPY --from=builder /build/comment-service/target/*.jar app.jar

# Прописываем точку входа
ENTRYPOINT ["java", "-jar", "app.jar"]
