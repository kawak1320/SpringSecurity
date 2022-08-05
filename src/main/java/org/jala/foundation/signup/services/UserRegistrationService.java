package org.jala.foundation.signup.services;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;

import java.util.UUID;

import org.jala.foundation.signup.exceptions.CognitoUserException;
import org.jala.foundation.signup.models.UserSignUp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
@Service
public class UserRegistrationService {
    @Value(value = "${aws.cognito.userPoolId}")
    private String userPoolId;
    @Value(value = "${aws.cognito.clientId}")
    private String clientId;
    @Autowired
    private AWSCognitoIdentityProvider cognitoClient;
    public String signUp(UserSignUp userSignUpRequest) throws CognitoUserException {

        String userStatus = null;
        try {

            AttributeType emailAttr =
                    new AttributeType().withName("email").withValue(userSignUpRequest.getEmail());
            AttributeType emailVerifiedAttr =
                    new AttributeType().withName("email_verified").withValue("true");

            AdminCreateUserRequest userRequest = new AdminCreateUserRequest()
                    .withUserPoolId(userPoolId)
                    .withUsername(userSignUpRequest.getUsername())
                    .withTemporaryPassword("MegaMindNewUser#001")
                    .withUserAttributes(emailAttr, emailVerifiedAttr)
                    .withMessageAction(MessageActionType.SUPPRESS)
                    .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL);

            AdminCreateUserResult createUserResult = cognitoClient.adminCreateUser(userRequest);

            userStatus = createUserResult.getUser().getUserStatus();
            System.out.println("User " + createUserResult.getUser().getUsername()
                    + " is created. Status: " + userStatus);

        } catch (AWSCognitoIdentityProviderException e) {
            System.out.println(e.getErrorMessage());
            throw new CognitoUserException("Cognito Provider error: " + e.getErrorMessage());
        } catch (Exception e) {
            System.out.println("Setting user password");
            throw new CognitoUserException("Setting user password");
        }
        return userStatus;
    }
    private String createTemporaryPassword() {
        return UUID.randomUUID().toString();
    }
}
