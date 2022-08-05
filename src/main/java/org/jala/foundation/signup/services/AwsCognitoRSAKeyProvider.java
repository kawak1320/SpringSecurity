package org.jala.foundation.signup.services;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
public class AwsCognitoRSAKeyProvider implements RSAKeyProvider {
    private final JwkProvider provider;
    private String jwkUrl;
    public AwsCognitoRSAKeyProvider(String jwkUrl) {

        try {
            this.jwkUrl = jwkUrl;
            URL awsStoreUrl = new URL(jwkUrl);
            provider = new JwkProviderBuilder(awsStoreUrl).build();
        } catch (MalformedURLException e) {
            throw new RuntimeException(String.format("Invalid URL provided, URL=%s", jwkUrl));
        }
    }
    @Override
    public RSAPublicKey getPublicKeyById(String kid) {
        try {
            return (RSAPublicKey) provider.get(kid).getPublicKey();
        } catch (JwkException e) {
            throw new RuntimeException(String.format("Failed to get JWT kid=%s from aws_kid_store_url=%s", kid, jwkUrl));
        }
    }
    @Override
    public RSAPrivateKey getPrivateKey() {
        return null;
    }
    @Override
    public String getPrivateKeyId() {
        return null;
    }
}