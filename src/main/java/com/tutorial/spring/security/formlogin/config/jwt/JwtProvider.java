package com.tutorial.spring.security.formlogin.config.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${jwt.secret.key}")
    private String jwtSecretKey;

    public boolean validateJwt(String token, HttpServletRequest request) {
        try {
            Jwts.parser().setSigningKey(jwtSecretKey).parseClaimsJwt(token);
            return true;
        } catch (MalformedJwtException exception) {
            logger.error("Invalid JWT token -> Message: {0}", exception);
        } catch (ExpiredJwtException exception) {
            logger.error("Expired JWT token -> Message: {0}", exception);
        } catch (IllegalArgumentException exception) {
            logger.error("JWT claims string is empty -> Message: {0}", exception);
        }
        return false;
    }

    public String getSubjectFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecretKey).parseClaimsJwt(token).getBody().getSubject();
    }
}
