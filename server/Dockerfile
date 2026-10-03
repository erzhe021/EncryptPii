FROM eclipse-temurin:17-jre

WORKDIR /app
COPY build/libs/*-SNAPSHOT.jar app.jar
USER 10001:10001
EXPOSE 9090
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
