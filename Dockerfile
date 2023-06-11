FROM harbor.tegical.com/mirror/docker.io/library/maven:3.8.1-amazoncorretto-11 as builder

WORKDIR /app

mvn package
