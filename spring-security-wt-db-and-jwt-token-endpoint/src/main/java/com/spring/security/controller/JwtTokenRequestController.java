package com.spring.security.controller;

import com.spring.security.config.JwtConfig;
import com.spring.security.payload.UsernameAndPasswordAuthenticationRequest;
import com.spring.security.payload.UsernameAndPasswordAuthenticationResponse;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.util.Date;

@RestController
@RequestMapping("/authenticate")
@AllArgsConstructor
public class JwtTokenRequestController {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenRequestController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @PostMapping
    public ResponseEntity<?> createAuthenticationToken(@RequestBody UsernameAndPasswordAuthenticationRequest request) throws Exception {
        LOGGER.info("Start Jwt token generate {}", request.getUsername());
        String jwtToken = null;
        Authentication authResult = null;
        try {
            Authentication authentication = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
            authResult = this.authenticationManager.authenticate(authentication);
        } catch (BadCredentialsException e) {
            LOGGER.error("Error in Authenticating username and password " + e.getMessage());
            throw new Exception("Invalid username or Password");
        }

        //token validity period
        long nowMillis = System.currentTimeMillis();
        Date expireDate = new Date(nowMillis + this.jwtConfig.getValidityPeriod() * 1000);

        jwtToken = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(this.secretKey)
                .compact();

        LOGGER.info("End Jwt token generate {} -> {}", request.getUsername(), jwtToken);
        return ResponseEntity.ok(UsernameAndPasswordAuthenticationResponse
                .builder()
                .jwtToken(jwtToken)
                .build());
    }
}
