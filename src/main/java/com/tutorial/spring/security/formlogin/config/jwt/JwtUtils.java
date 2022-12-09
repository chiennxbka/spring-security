package com.tutorial.spring.security.formlogin.config.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;

@Component
public class JwtUtils {
    @Value("${jwt.duration}")
    private long duration;

    @Value("${jwt.secret.key}")
    private String secret;

    public String generateJwtToken(String subject) {
        return Jwts.builder().setSubject(subject).setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusSeconds(duration)))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }
}
