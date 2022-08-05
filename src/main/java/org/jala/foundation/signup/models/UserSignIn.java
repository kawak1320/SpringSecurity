package org.jala.foundation.signup.models;

import lombok.Getter;
import lombok.Setter;
@Getter
@Setter
public class UserSignIn {
    private String username;
    private String email;
    private String password;
    private String newPassword;
}
