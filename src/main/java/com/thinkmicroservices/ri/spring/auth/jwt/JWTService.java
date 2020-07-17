/*
 * Copyright 2019 cwoodward.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.thinkmicroservices.ri.spring.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.util.Date;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 *
 * @author cwoodward
 */
@Service
@Slf4j
public class JWTService {

    @Value("${jwt.secret:thinkmicroservices}")
    private String jwtSecret="thinkmicroservices";
    public static final String JWT_ACCOUNT_ID = "accountID";
    protected static final String JWT_REQUEST_ATTRIBUTE = "JWT";

    public JWT decodeJWT(String token) {
        log.debug("token=>{}", token);
        Jws<Claims> jws = Jwts.parser()
                //.setSigningKey(jwtSecret.getBytes("UTF-8"))
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token);

        JWT jwt = JWT.builder()
                .subject(jws.getBody().getSubject())
                .accountId(jws.getBody().get(JWT_ACCOUNT_ID, String.class))
                .issuedAt(jws.getBody().getIssuedAt())
                .expiresAt(jws.getBody().getExpiration())
                .roles((List<String>) jws.getBody().get("roles"))
                .build();

        log.debug("JWT=>{}", jwt);
        return jwt;

    }

    /**
     * prior to the controller's invocation, the JWTFilter extracts the
     * Authorization token from the request and creates a JWT instance and adds
     * it as an attribute to the inbound request. This helper method extracts
     * the JWT
     */
    public JWT getJWT(HttpServletRequest httpServletRequest) {
        log.debug("getJWT()");
        Object obj = httpServletRequest.getAttribute(JWT_REQUEST_ATTRIBUTE);

        if ((obj != null) && (obj instanceof JWT)) {
            JWT jwt = (JWT) obj;
            log.debug("JWT=>{}", jwt);
            return jwt;
        } else {
            log.warn("no JWT set in the request");
        }
        // no JWT for you!
        return null;
    }
}
