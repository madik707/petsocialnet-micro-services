# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

# Копируем pom.xml и зависимости отдельно для кеширования
COPY eureka-server/pom.xml eureka-server/
RUN mvn -f eureka-server/pom.xml dependency:go-offline

# Копируем исходники и собираем, пропуская тесты
COPY eureka-server /build/eureka-server
RUN mvn -f eureka-server/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app

# Копируем собранный JAR из предыдущего этапа
COPY --from=builder /build/eureka-server/target/*.jar app.jar

# Прописываем точку входа
ENTRYPOINT ["java", "-jar", "app.jar"]
