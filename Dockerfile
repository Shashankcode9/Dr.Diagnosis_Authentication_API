# Use official OpenJDK image
FROM openjdk:17-jdk-alpine

# Copy the jar file
COPY target/auth-0.0.1-SNAPSHOT.jar app.jar

# Expose port (default 8080)
EXPOSE 8080

# Run the jar file
ENTRYPOINT ["java","-jar","/app.jar"]