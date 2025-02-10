package com.civilink.user_service_api.api;


import com.civilink.user_service_api.dto.User;
import com.civilink.user_service_api.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
        System.out.println(username +","+ password);
        return userService.login(username,password);
    }

    @PostMapping("/verify")
    public ResponseEntity<Boolean> verifyToken(
            @RequestParam String authToken
    ){
        System.out.println(authToken);
        String token = authToken.replace("Bearer ", "");

        Boolean isValid = userService.validateToken(token);
        return ResponseEntity.ok(isValid);
    }

    @GetMapping("/user-group")
    public String getUserGroup(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        List<String> groups = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(role->role.startsWith("ROLE_"))
                .map(role->role.substring(5))
                .collect(Collectors.toList());


        return groups.isEmpty()? "No groups found" : String.join(", ", groups);
    }
}
