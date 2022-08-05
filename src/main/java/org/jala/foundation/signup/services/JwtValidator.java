package org.jala.foundation.signup.services;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.lambda.runtime.Context;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.jala.foundation.signup.handlers.LambdaHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
@Component
public class JwtValidator {
    private static final Logger logger = LoggerFactory.getLogger(JwtValidator.class);
    @Value(value = "${aws.cognito.userPoolId}")
    private String userPoolId;
    @Autowired
    private AwsCognitoRSAKeyProvider provider;
    public boolean validateUserName(String userPoolId, AWSCognitoIdentityProvider cognitoClient, String userName) {

        LambdaHandler lambdaHandler = new LambdaHandler();
        lambdaHandler.setUsername(userName);
        lambdaHandler.setCognitoClient(cognitoClient);
        lambdaHandler.setUserPoolId(userPoolId);

        InputStream input = null;
        OutputStream output = null;
        Context context = null;

        try {
            lambdaHandler.handleRequest(input, output, context);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return true;
    }
    public boolean validateJwtToken(String authToken) {

        try {
            Algorithm algorithm = Algorithm.RSA256(provider);
            JWTVerifier jwtVerifier = JWT.require(algorithm).build();

            // verificar si el token ha expirado

            var subject = JWT.decode(authToken).getSubject();
            var email = JWT.decode(authToken).getClaim("email");
            // TODO: Validate email and subject against our database (user-service)

            jwtVerifier.verify(authToken);

            return true;

        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
//        } catch (IOException e) {
//            throw new RuntimeException(e);
        }
        return false;
    }
}