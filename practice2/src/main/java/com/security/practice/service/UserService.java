package com.security.practice.service;

import com.security.practice.domain.Role;
import com.security.practice.domain.User;
import com.security.practice.dto.UserDto;
import com.security.practice.repository.RoleRepo;
import com.security.practice.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("--------{}------------", username );
        User user = userRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found in the database"));
        if (user == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found in the database: {}", username);
        }
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role ->
                        new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Transactional
    public User signup(UserDto userDto) {
        if (userRepo.findOneWithRolesByUsername(userDto.getNickname()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Role role = new Role("ROLE_USER");
        Role role1 = new Role("ROLE_ADMIN");
        List<Role> roles = new ArrayList<>();
        roles.add(role);
        roles.add(role1);
        User user = User.builder()
                        .username(userDto.getUsername())
                        .password(passwordEncoder.encode(userDto.getPassword()))
                        .name(userDto.getNickname())
                        .roles(roles).build();
        return userRepo.save(user);
    }
    public User saveUser(User user) {
        log.info("Saving new User {} to the database", user.getName());
        return userRepo.save(user);
    }

    public Role saveRole(Role role) {
        log.info("Saving new Role {} to the database", role.getName());
        return roleRepo.save(role);
    }

    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);
        User user = userRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found in the database"));
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    public User getUser(String username) {
        return userRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found in the database"));
    }

    public List<User> getUsers() {
        return userRepo.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepo.findByUsername(username);
    }
}
