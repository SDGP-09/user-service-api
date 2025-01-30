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


    @PostMapping("/create")
    public ResponseEntity<String> createUser(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody User user
            ){

        String requestToken = authHeader.replace("Bearer ", "");

        try{
            userService.createUser(
                    requestToken,
                    user.getFirstName(),
                    user.getPassword(),
                    user.getFirstName(),
                    user.getLastName(),
                    user.getEmail(),
                    user.getGroupName(),
                    user.getUserRoles()
            );

            return ResponseEntity.ok("User create successfully");

        }catch (SecurityException e){
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error creating user.");
        }


    }

    @PostMapping("/login")
    public Object login(
            @RequestParam String username, @RequestParam String password
    ){
        return userService.login(username,password);
    }
}
