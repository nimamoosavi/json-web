package com.nicico.cost.jsonweb.service.config;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(value = "classpath:json-web-exception.properties", encoding = "UTF-8", ignoreResourceNotFound = true)
public class JsonWebConfig {

    public static String secretKey;

    public static SignatureAlgorithm signatureAlgorithm;


    @Value("${json.web.toke.secretKey:123}")
    public void setSecretAppKeys(String secretAppKeys) {
        JsonWebConfig.secretKey = secretAppKeys;
    }

    @Value("${json.web.toke.signatureAlgorithm:HS512}")
    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        JsonWebConfig.signatureAlgorithm = signatureAlgorithm;
    }
}
