package eu.pomoku.backend.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${jwt.secretKey}")
    private String secretKey;
    @Value("${jwt.expiration.accessToken}")
    private long accessTokenExpiration;
    @Value("${jwt.expiration.refreshToken}")
    private long refreshTokenExpiration;

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC512(secretKey);
    }

    public String getJwtFromHeader(HttpServletRequest request) {
        String barierToken = request.getHeader("Authorization");
        if (barierToken != null && barierToken.startsWith("Bearer ")) {
            return barierToken.substring(7);
        }
        return null;
    }

    public String extractUsername(String token) {
        return decodeToken(token).getSubject();
    }

    public Collection<? extends GrantedAuthority> extractRoles(String token) {
        List<String> roles = decodeToken(token).getClaim("roles").asList(String.class);
        return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }


    private DecodedJWT decodeToken(String token) {
        JWTVerifier verifier = JWT.require(getAlgorithm()).build();
        return verifier.verify(token);
    }
}
