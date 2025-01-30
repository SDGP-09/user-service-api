package com.civilink.user_service_api.api;


import com.civilink.user_service_api.dto.User;
import com.civilink.user_service_api.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired
    private UserService userService;

//    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/create")
    public void createUser(
            @RequestBody User user
            ){
//        String token = userService.getAccessToken();
//
//        String url = "http://localhost:8080/admin/realms/civilink/users";
//
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_JSON);
//        headers.setBearerAuth(token); // Add the token here
//
//        Map<String, Object> userPayload = new HashMap<>();
//        userPayload.put("username", user.getUsername());
//        userPayload.put("firstName", user.getFirstName());
//        userPayload.put("lastName", user.getLastName());
//        userPayload.put("email", user.getEmail());
//        userPayload.put("enabled", true);
//
//        Map<String, String> credentials = new HashMap<>();
//        credentials.put("type", "password");
//        credentials.put("value", "1234");
//        credentials.put("temporary", "false");
//        userPayload.put("credentials", List.of(credentials));
//
//        HttpEntity<Map<String, Object>> request = new HttpEntity<>(userPayload, headers);
//        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);
//
//        if (!response.getStatusCode().is2xxSuccessful()) {
//            throw new RuntimeException("Failed to create user: " + response.getBody());
//        }

        System.out.println("===============================================");
        userService.createUser(
                user.getFirstName(), user.getPassword(), user.getFirstName(), user.getLastName(), user.getEmail(), user.getGroupName(), user.getUserRoles()
        );
    }

    @PostMapping("/login")
    public Object login(
            @RequestParam String username, @RequestParam String password
    ){
        System.out.println(username);
        System.out.println(password);

        return userService.login(username,password);
    }
}
