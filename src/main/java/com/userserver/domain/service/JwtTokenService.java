package com.userserver.domain.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;

@Service
public class JwtTokenService {

    private String secret = "SADKAOSDKA@!%!@SDA";

    public String createToken(UserDetails userDetails){
        return  JWT.create().withSubject(userDetails.getUsername())
                .withClaim("role",userDetails.getAuthorities().toString())
                .withExpiresAt(Instant.now().atOffset(ZoneOffset.of("-03:00")).toInstant())
                .sign(Algorithm.HMAC256(secret));
    }

    public String getSubject(String token){
        return JWT.decode(token).getSubject();
    }

    public boolean isInvalid(String token){
        return JWT.decode(token).getExpiresAt().after(Date.from(Instant.now().atOffset(ZoneOffset.of("-03:00")).toInstant()));
    }

}
