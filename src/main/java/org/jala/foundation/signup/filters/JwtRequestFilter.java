package org.jala.foundation.signup.filters;

import org.jala.foundation.signup.configurations.ConfigurationConstants;
import org.jala.foundation.signup.services.JwtValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer ";
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRequestFilter.class);

    @Autowired
    private JwtValidator jwtValidator;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!isPublicUrl(request.getRequestURI())) {
            String token = parseToken(request);
            String json = "{\"Token \":\""+token+"\"}";
            LOGGER.info("Extracted token: " + token);
            String jwtValidatorVar = jwtValidator.runWithPayload("us-east-2", "arn:aws:lambda:us-east-2:077492956248:function:jwtMpToken", json);
            LOGGER.info("JWT validator response: " + jwtValidatorVar);
        }
        filterChain.doFilter(request, response);
    }
    private String parseToken(HttpServletRequest request) {
        final String authorizationValue = request.getHeader(AUTHORIZATION);
        if (authorizationValue != null && authorizationValue.startsWith(BEARER)) {
            return authorizationValue.substring(7);
        }
        return null;
    }
    private boolean isPublicUrl(String incomingUri) {
        return ConfigurationConstants.permitAllEndpointList.contains(incomingUri);
    }
}