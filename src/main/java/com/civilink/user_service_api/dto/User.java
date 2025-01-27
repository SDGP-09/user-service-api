package com.civilink.user_service_api.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private String groupName;
    private String userRoles;
}
