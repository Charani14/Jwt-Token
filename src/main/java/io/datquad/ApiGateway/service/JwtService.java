package io.datquad.ApiGateway.service;

import io.datquad.ApiGateway.model.Token;
import io.datquad.ApiGateway.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Optional;

@Service
public class JwtService {

    private final Key key;
    private final long validityInMilliseconds = 1800000; // 30 minutes
    private final TokenRepository tokenRepository;

    // Inject secret key from properties file
    public JwtService(@Value("${jwt.secret}") String secretKey, TokenRepository tokenRepository) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.tokenRepository = tokenRepository;
    }

    // Validate the token against the database
    public boolean validateToken(String token) {
        try {
            Claims claims = getClaims(token);
            String email = claims.getSubject();

            // Look for the token in the database by email
            Optional<Token> storedToken = tokenRepository.findByToken(token);

            if (storedToken.isPresent()) {
                Token tokenRecord = storedToken.get();

                // Check if the token is expired
                if (tokenRecord.isExpired()) {
                    throw new IllegalStateException("Token is expired. Please log in again.");
                }

                // Check if the token is revoked
                if (tokenRecord.isRevoked()) {
                    throw new IllegalStateException("Token is revoked. Please log in again.");
                }

                // Validate that the token is still valid (not expired)
                return !claims.getExpiration().before(new Date());
            } else {
                throw new IllegalStateException("Token not found in the database.");
            }

        } catch (Exception e) {
            // Handle any exceptions (invalid token format, expired, revoked, etc.)
            return false;
        }
    }

    // Extract the username (email) from the token
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // Extract claims from the token
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
