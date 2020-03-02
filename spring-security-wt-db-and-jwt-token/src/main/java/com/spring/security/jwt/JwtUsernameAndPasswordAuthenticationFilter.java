package com.spring.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.security.config.JwtConfig;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUsernameAndPasswordAuthenticationFilter.class);

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @Autowired
    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                      JwtConfig jwtConfig,
                                                      SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
            Authentication authentication = new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword());
            final Authentication authenticate = this.authenticationManager.authenticate(authentication);
            return authenticate;
        } catch (IOException e) {
            LOGGER.error("Error in JwtAuthenticationFilter attemptAuthentication method " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        //final LocalDate date = LocalDateTime.now().plusMinutes(15).toLocalDate();
        //token validity period
        long nowMillis = System.currentTimeMillis();
        Date expireDate = new Date(nowMillis + this.jwtConfig.getValidityPeriod() * 1000);

        String token = Jwts.builder()
                        .setSubject(authResult.getName())
                        .claim("authorities", authResult.getAuthorities())
                        .setIssuedAt(new Date())
                        .setExpiration(expireDate)
                        .signWith(this.secretKey)
                        .compact();

        response.setHeader(this.jwtConfig.getAuthorizationHeader(), this.jwtConfig.getTokenPrefix().concat(" ") + token);
    }
}
