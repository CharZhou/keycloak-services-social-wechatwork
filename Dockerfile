FROM harbor.tegical.com/mirror/docker.io/library/maven:3.8.1-amazoncorretto-11 as builder

WORKDIR /app
COPY . /app
COPY settings.xml /root/.m2/settings.xml

RUN mvn clean package -Dmaven.test.skip=true -Denforcer.skip=true -T 1C

FROM scratch
COPY --from=builder /app/target/keycloak-services-social-wework.jar /app.jar
