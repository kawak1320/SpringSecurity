package org.jala.foundation.signup.handlers;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.ListUsersRequest;
import com.amazonaws.services.cognitoidp.model.ListUsersResult;
import com.amazonaws.services.cognitoidp.model.UserType;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
public class LambdaHandler implements RequestStreamHandler{
    private String userName;
    public void setUsername(String userName) {
        this.userName = userName;
    }
    private AWSCognitoIdentityProvider cognitoClient;
    public void setCognitoClient(AWSCognitoIdentityProvider cognitoClient) {
        this.cognitoClient = cognitoClient;
    }
    private String userPoolId;
    public void setUserPoolId(String userPoolId) {
        this.userPoolId = userPoolId;
    }
    @Override
    public void handleRequest(InputStream input, OutputStream output, Context context) throws IOException {

        System.out.println("cognitoClient: " + cognitoClient);

        ListUsersResult listUsersResult = listAllUsers(userPoolId, cognitoClient);

        for (UserType user : listUsersResult.getUsers()) {
            if(userName.equals(user.getUsername())){
                System.out.println("The valid user is: " + user.getUsername());
            }
        }
    }
    public ListUsersResult listAllUsers(String userPoolId, AWSCognitoIdentityProvider cognitoClient) {
        ListUsersRequest listUsersRequest = new ListUsersRequest();
        listUsersRequest.setUserPoolId(userPoolId);
        ListUsersResult listUsersResult = cognitoClient.listUsers(listUsersRequest);
        for (UserType user : listUsersResult.getUsers()) {
            System.out.println("User: " + user.getUsername());
        }
        return listUsersResult;
    }
}
