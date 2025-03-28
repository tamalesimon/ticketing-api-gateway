FROM openjdk:21
WORKDIR /app
COPY target/api-gateway-0.0.1-SNAPSHOT.jar api-gateway.jar
ENTRYPOINT ["java", "-Dspring.profiles.active=docker", "-jar", "api-gateway.jar"]
EXPOSE 8080