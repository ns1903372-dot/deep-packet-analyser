FROM eclipse-temurin:21-jdk

WORKDIR /app

COPY src ./src
COPY sample-data ./sample-data
COPY pom.xml ./
COPY README.md ./

RUN mkdir -p out && javac -d out src/main/java/com/ns1903372dot/dpi/*.java

EXPOSE 7860

ENV PORT=7860

CMD ["java", "-cp", "out", "com.ns1903372dot.dpi.SpaceServer"]

