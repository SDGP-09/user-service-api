package com.civilink.user_service_api.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.civilink.user_service_api.dto.User;

import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.server-id}")
    private String serverUrl;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    @Value("${keycloak.api-url}")
    private String apiUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    public void createUser(
            String reqToken, String userName, String password, String firstName, String lastName, String email, String groupName, String userRoles
    ){


        Keycloak keycloak = getKeyCloakInstance(reqToken);

        String requesterUserId = getRequesterUserId(reqToken);
        List<String> requesterGroups = getUserGroups(keycloak, requesterUserId);

        if (!requesterGroups.contains(groupName)) {
            throw new SecurityException("Requester does not belong to the specified group: " + groupName);
        }


        User user = User.builder().username(userName)
                .password(password)
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .build();

        UserRepresentation userRep = mapUser(user);



        Response response = keycloak.realm(realm).users().create(userRep);

        if (response.getStatus() == Response.Status.CREATED.getStatusCode()){
           // RoleRepresentation userRole = keycloak.realm(realm).roles().get("user").toRepresentation();

            String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

            assignRoleToUser(keycloak,userId,userRoles);
            assignUserToGroup(keycloak,userId,groupName);
        }

    }

    private UserRepresentation mapUser(User user){
        UserRepresentation ur = new UserRepresentation();
        ur.setUsername(user.getUsername());
        ur.setLastName(user.getLastName());
        ur.setFirstName(user.getFirstName());
        ur.setEmail(user.getEmail());

        ur.setEnabled(true);
        ur.setEmailVerified(true);

        List<CredentialRepresentation> creds = new ArrayList<>();
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setTemporary(false);
        credentialRepresentation.setValue(user.getPassword());
        creds.add(credentialRepresentation);

        ur.setCredentials(creds);

        return ur;

    }

    private Keycloak getKeyCloakInstance(String token){
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .authorization(token)
                .clientSecret(clientSecret)
                .clientId(clientId)
                .build();
    }

    public void assignUserToGroup(Keycloak keycloak,String userId, String groupName){
        List<GroupRepresentation> groups = keycloak.realm(realm).groups().groups();

        for (GroupRepresentation group : groups){
            if (group.getName().equals(groupName)){
                keycloak.realm(realm).users().get(userId).joinGroup(group.getId());
                break;
            }
        }
    }

    public void assignRoleToUser(Keycloak keycloak,String userId, String roleName){
        RoleRepresentation userRole = keycloak.realm(realm).roles().get(roleName).toRepresentation();
        keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
    }

    public Object login(String username, String password){
        MultiValueMap<String,String> requestBody = new LinkedMultiValueMap<>();

        requestBody.add("client_id",clientId);
        requestBody.add("grant_type", OAuth2Constants.PASSWORD);
        requestBody.add("username",username);
        requestBody.add("client_secret",clientSecret);
        requestBody.add("password",password);

        String keyCloakApiUrl = apiUrl;

        HttpHeaders headers = new HttpHeaders();

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<Object> response = restTemplate.postForEntity(keyCloakApiUrl,requestBody, Object.class);

        return response.getBody();
    }

    public String getAccessToken() {
        String tokenUrl = "http://localhost:8080/realms/civilink/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String body = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret;

        HttpEntity<String> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, Map.class);

        return (String) response.getBody().get("access_token");
    }

    public String getRequesterUserId(String requestToken){
        DecodedJWT decodedJWT = JWT.decode(requestToken);
        return decodedJWT.getClaim("sub").asString();
    }

    private List<String> getUserGroups(Keycloak keycloak, String userId) {
        List<GroupRepresentation> groups = keycloak.realm(realm).users().get(userId).groups();
        return groups.stream().map(GroupRepresentation::getName).collect(Collectors.toList());
    }

}
