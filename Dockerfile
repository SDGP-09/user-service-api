FROM openjdk:17

COPY target/user-management-api.jar .

EXPOSE 6060

ENTRYPOINT ["java","-jar","user-management-api.jar"]