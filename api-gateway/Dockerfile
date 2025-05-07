# --- Stage 1: Build ---
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

# Копируем pom.xml и зависимости отдельно для кеширования
COPY api-gateway/pom.xml api-gateway/
RUN mvn -f api-gateway/pom.xml dependency:go-offline

# Копируем исходники и собираем
COPY api-gateway /build/api-gateway
RUN mvn -f api-gateway/pom.xml clean package -DskipTests

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17
WORKDIR /app

# Копируем собранный JAR из предыдущего этапа
COPY --from=builder /build/api-gateway/target/*.jar app.jar

# Прописываем точку входа
ENTRYPOINT ["java", "-jar", "app.jar"]
