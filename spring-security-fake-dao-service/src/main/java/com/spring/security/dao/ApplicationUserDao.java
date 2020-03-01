package com.spring.security.dao;

import com.spring.security.model.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserDao {
    Optional<ApplicationUser> loadUserByUsername(String username);
}
