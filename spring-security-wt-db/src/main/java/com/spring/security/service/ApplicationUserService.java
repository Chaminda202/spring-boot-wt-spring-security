package com.spring.security.service;

import com.spring.security.model.ApplicationUser;
import com.spring.security.model.User;
import com.spring.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ApplicationUserService implements UserDetailsService {
    private UserRepository userRepository;

    @Autowired
    public ApplicationUserService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userObject = this.userRepository.findByUsername(username);
        userObject.orElseThrow(() -> new UsernameNotFoundException(String.format("Username %s is not found", username)));
        UserDetails userDetails = new ApplicationUser(userObject.get());
        return userDetails;
    }
}
