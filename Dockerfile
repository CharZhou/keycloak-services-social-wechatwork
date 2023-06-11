FROM harbor.tegical.com/mirror/docker.io/library/maven:3.8.1-amazoncorretto-11 as builder

WORKDIR /app
COPY . /app

RUN mvn clean package -DskipTests

FROM scratch
COPY --from=builder /app/target/keycloak-services-social-wework.jar /app.jar
