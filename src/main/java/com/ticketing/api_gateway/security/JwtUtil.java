package com.ticketing.api_gateway.security;

import java.util.Date;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${security.secret-key}")
    private String secretKey;

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody();
            logger.info("Successfully extracted claims from token.");
            return claimsResolver.apply(claims);
        } catch (ExpiredJwtException e) {
            logger.warn("Token has expired: {}", token, e);
            throw new IllegalArgumentException("The provided token has expired.", e);
        } catch (MalformedJwtException e) {
            logger.warn("Malformed token: {}", token, e);
            throw new IllegalArgumentException("The provided token is malformed.", e);
        } catch (SignatureException e) {
            logger.warn("Invalid token signature: {}", token, e);
            throw new IllegalArgumentException("The token signature is invalid.", e);
        } catch (Exception e) {
            logger.error("Failed to parse token: {}", token, e);
            throw new IllegalArgumentException("An error occurred while parsing the token.", e);
        }
    }

    public boolean validateToken(String token) {
        return !extractClaim(token, Claims::getExpiration).before(new Date());
    }

}
