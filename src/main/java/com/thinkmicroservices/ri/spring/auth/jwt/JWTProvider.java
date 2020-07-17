package com.thinkmicroservices.ri.spring.auth.jwt;

import com.thinkmicroservices.ri.spring.auth.repository.model.User;
import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.ArrayList;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.GrantedAuthority;
/**
 * 
 * @author cwoodward
 */
@Component
public class JWTProvider implements Serializable {

    private static Logger logger = LoggerFactory.getLogger(JWTProvider.class);
    private static final long serialVersionUID = -2550185165626007488L;

     
    private static final String JWT_ROLES = "roles";
    private static final String JWT_SUBJECT = "sub";
    private static final String JWT_ISSUED_AT="iat";
    private static final String JWT_EXPIRES_AT="exp";
    private static final String JWT_ISSUED = "iss";
    private static final String JWT_REFRESH_TOKEN="refresh_token";
    private static final String JWT_REFRESH_TOKEN_EXPIRATION="refresh_token_exp";
    public static final String JWT_ACCOUNT_ID = "accountID";
    
    
    // the configuration defaults should all be overridden
    // at runtime with deployment-specific values.
    
    
    @Value("${jwt.token.valid.interval.secs:60}")
    private long jwtTokenValidIntervalSecs=60;
    
    /**
     * the <b>secret</b> is used to sign the token
     */
    @Value("${jwt.secret:thinkmicroservices}")
    private String secret="thinkmicroservices";
    
    /**
     * 
     */
    @Value("${jwt.issuer:Authentication-Service}")
    private String issuer;

    /**
     * 
     * @param token
     * @return 
     */
    
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * 
     * @param token
     * @return 
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * 
     * @param <T>
     * @param token
     * @param claimsResolver
     * @return 
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

     
    /**
     * 
     * @param token
     * @return 
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    /**
     * 
     * @param token
     * @return 
     */
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * 
     * @param user
     * @param authorities
     * @param issuedAt
     * @param expiresAt
     * @param refreshToken
     * @param refreshTokenExpiration
     * @return 
     */
    public String generateToken(User  user, ArrayList<GrantedAuthority> authorities,long issuedAt, long expiresAt,  String refreshToken, long refreshTokenExpiration) {
        Map<String, Object> claims = new HashMap<>();

        String[] roles = new String[authorities.size()];
        int idx = 0;
        for (GrantedAuthority auth : authorities) {
            roles[idx++] = auth.getAuthority();
        }
        claims.put(JWT_ISSUED_AT,issuedAt);
        claims.put(JWT_EXPIRES_AT,expiresAt);

        claims.put(JWT_SUBJECT, user.getUsername());
        logger.info( "roles=>"+JWT_ROLES,
                String.join(",", Arrays.asList(roles))
        );
        claims.put(JWT_ROLES, roles);
        claims.put(JWT_ISSUED, issuer);
        claims.put(JWT_ACCOUNT_ID,user.getAccountId());
        claims.put(JWT_REFRESH_TOKEN,refreshToken);
        claims.put(JWT_REFRESH_TOKEN_EXPIRATION, refreshTokenExpiration);
        
        return buildJwtToken(claims, user.getUsername());
    }
    

    /**
     * 
     * @param claims
     * @param subject
     * @return 
     */
    private String buildJwtToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (jwtTokenValidIntervalSecs*1000)))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

   /**
    * 
    * @param token
    * @param userDetails
    * @return 
    */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
