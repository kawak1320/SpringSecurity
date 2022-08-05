package org.jala.foundation.signup.controllers;

import org.jala.foundation.signup.exceptions.CognitoUserException;
import org.jala.foundation.signup.models.UserDetail;
import org.jala.foundation.signup.models.UserSignIn;
import org.jala.foundation.signup.models.UserSignInResponse;
import org.jala.foundation.signup.models.UserSignUp;
import org.jala.foundation.signup.services.UserAuthenticationService;
import org.jala.foundation.signup.services.UserRegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping(path = "/api/users")
public class UserController {
    @Autowired
    private UserRegistrationService userRegistrationService;
    @Autowired
    private UserAuthenticationService userAuthenticationService;
    @PostMapping(path = "/sign-up")
    public String signUp(@RequestBody UserSignUp userSignUpRequest) throws CognitoUserException {
        return userRegistrationService.signUp(userSignUpRequest);
    }
    @PostMapping(path = "/sign-in")
    public @ResponseBody  UserSignInResponse signIn(@RequestBody UserSignIn userSignInRequest) throws CognitoUserException {
        return userAuthenticationService.signIn(userSignInRequest);
    }
    @GetMapping(path = "/details")
    public @ResponseBody  UserDetail getUserDetail() {

        UserDetail userDetail = new UserDetail();
        userDetail.setFirstName("TestUser");
        userDetail.setLastName("BuddyG");
        userDetail.setEmail("testbuddya@tutotialsbuddy.com");
        return userDetail;
    }
}
