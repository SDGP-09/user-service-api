# Stage 1: Build the application
FROM maven:3.8.6-amazoncorretto-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests

# Stage 2: Create the final image
FROM openjdk:17-alpine
WORKDIR /app
COPY --from=build /app/target/user-management-api.jar .

EXPOSE 9090
CMD ["java", "-jar", "user-management-api.jar"]