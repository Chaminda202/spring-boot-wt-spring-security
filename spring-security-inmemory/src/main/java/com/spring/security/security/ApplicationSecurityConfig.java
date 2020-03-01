package com.spring.security.security;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.spring.security.security.UserPermission.COURSE_WRITE;
import static com.spring.security.security.UserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@AllArgsConstructor
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private PasswordEncoder passwordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
               // .csrf().disable()
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                .antMatchers("/", "/index.html").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
               /* .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())*/
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        final UserDetails user = User.builder()
                .username("user")
                .password(this.passwordEncoder.encode("user"))
               // .roles(STUDENT.name())
                .authorities(STUDENT.grantedAuthority())
                .build();

        final UserDetails admin = User.builder()
                .username("admin")
                .password(this.passwordEncoder.encode("admin"))
              //  .roles(ADMIN.name())
                .authorities(ADMIN.grantedAuthority())
                .build();

        final UserDetails adminTrainee = User.builder()
                .username("admintrainee")
                .password(this.passwordEncoder.encode("admintrainee"))
              //  .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.grantedAuthority())
                .build();

        return new InMemoryUserDetailsManager(user, admin, adminTrainee);
    }
}
