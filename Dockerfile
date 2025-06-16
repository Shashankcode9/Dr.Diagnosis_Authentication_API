# Use Maven to build the app
FROM maven:3.9.3-eclipse-temurin-17-alpine as builder
COPY . .
RUN mvn clean package -DskipTests

# Final image with JAR only
FROM openjdk:17-jdk-alpine
COPY --from=builder target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app.jar"]
