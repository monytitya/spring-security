package security_spring_boot.demo.security;

import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

    private final String SECRET = "mysecretkey";

    // Generate Token
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000)) // 1 day
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    // Extract Claims
    public Claims extract(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }

    // Extract Username
    public String extractUsername(String token) {
        return extract(token).getSubject();
    }

    // Extract Role
    public String extractRole(String token) {
        return extract(token).get("role", String.class);
    }

    // Validate Token
    public boolean validateToken(String token) {
        try {
            extract(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}