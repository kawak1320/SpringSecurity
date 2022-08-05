package org.jala.foundation.signup.configurations;

import org.jala.foundation.signup.filters.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;

import java.util.Arrays;
import java.util.List;
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    public static final String SIGNUP_URL = "/api/users/sign-up";
    public static final String SIGNIN_URL = "/api/users/sign-in";
    @Autowired
    private JwtRequestFilter jwtRequestFilter;
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        List<String> permitAllEndpointList = Arrays.asList(SIGNUP_URL, SIGNIN_URL);

        http.cors().and().csrf().disable()
                .authorizeRequests(expressionInterceptUrlRegistry -> expressionInterceptUrlRegistry
                        .antMatchers(permitAllEndpointList.toArray(new String[permitAllEndpointList.size()]))
                        .permitAll().anyRequest().authenticated())
                .oauth2ResourceServer().jwt();

        http.addFilterBefore(jwtRequestFilter, BearerTokenAuthenticationFilter.class);
    }
}