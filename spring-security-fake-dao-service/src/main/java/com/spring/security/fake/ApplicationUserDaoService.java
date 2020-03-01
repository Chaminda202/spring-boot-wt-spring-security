package com.spring.security.fake;

import com.spring.security.dao.ApplicationUserDao;
import com.spring.security.model.ApplicationUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.spring.security.security.UserRole.*;

@Repository("fakeRepositoryService")
public class ApplicationUserDaoService implements ApplicationUserDao {
    private PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationUserDaoService(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    public Optional<ApplicationUser> loadUserByUsername(String username) {
        return getAllUser().stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getAllUser(){
        List<ApplicationUser> userList = List.of(
                new ApplicationUser("user",
                        this.passwordEncoder.encode("user"),
                        STUDENT.grantedAuthority(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser("admin",
                        this.passwordEncoder.encode("admin"),
                        ADMIN.grantedAuthority(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser("admintrainee",
                        this.passwordEncoder.encode("admintrainee"),
                        ADMINTRAINEE.grantedAuthority(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return userList;
    }
}