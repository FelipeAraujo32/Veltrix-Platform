# Build a partir da RAIZ do repositório (contexto = raiz, padrão reactor):
#   docker build -f security/auth-service/Dockerfile -t veltrix/auth-service:local .
FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml ./
COPY security/shared-security/pom.xml security/shared-security/pom.xml
COPY security/auth-service/pom.xml security/auth-service/pom.xml
COPY security/api-gateway/pom.xml security/api-gateway/pom.xml
COPY security/auth-service/src security/auth-service/src
RUN mvn -B -q -pl security/auth-service -am -DskipTests package

FROM eclipse-temurin:21-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system veltrix \
    && useradd --system --gid veltrix --home-dir /app veltrix
WORKDIR /app
COPY --from=build --chown=veltrix:veltrix /workspace/security/auth-service/target/auth-service-0.0.1-SNAPSHOT.jar /app/app.jar
USER veltrix
EXPOSE 8082
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl --fail --silent http://localhost:8082/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
