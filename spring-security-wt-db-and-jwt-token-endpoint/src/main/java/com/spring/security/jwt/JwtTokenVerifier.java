package com.spring.security.jwt;

import com.google.common.base.Strings;
import com.spring.security.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenVerifier.class);

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(this.jwtConfig.getAuthorizationHeader());

        if(!Strings.isNullOrEmpty(authorizationHeader)){
            if(!authorizationHeader.startsWith(this.jwtConfig.getTokenPrefix())){
                filterChain.doFilter(request, response);
                return;
            }

            String token = authorizationHeader.replace(this.jwtConfig.getTokenPrefix(), "");
            try{
                final Jws<Claims> claimsJws = Jwts.parserBuilder()
                        .setSigningKey(this.secretKey)
                        .build()
                        .parseClaimsJws(token);
                Claims body = claimsJws.getBody();
                String username = body.getSubject();
                var authorities = (List<Map<String, String>>)body.get("authorities");

                List<SimpleGrantedAuthority> authority = authorities.stream()
                        .map(stringStringMap -> new SimpleGrantedAuthority(stringStringMap.get("authority")))
                        .collect(Collectors.toList());
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        authority
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }catch (JwtException e){
                LOGGER.error("Token error "+ e.getMessage());
                throw new IllegalStateException(String.format("Token %s cannot be trust", token));
            }
        }
        filterChain.doFilter(request, response);
    }
}
