package com.civilink.user_service_api.api;


import com.civilink.user_service_api.dto.User;
import com.civilink.user_service_api.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/create")
    public void createUser(
            @RequestBody User user
            ){
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
