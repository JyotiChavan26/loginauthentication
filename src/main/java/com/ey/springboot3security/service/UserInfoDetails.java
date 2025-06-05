package com.ey.springboot3security.service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.ey.springboot3security.entity.UserInfo;

public class UserInfoDetails implements UserDetails {

    private final String username; // email as username
    private final String password;
    private final List<GrantedAuthority> authorities;

    public UserInfoDetails(UserInfo userInfo) {
        this.username = userInfo.getEmail();
        this.password = userInfo.getPassword();

        // Split roles string by comma and trim spaces
        // Only allow valid roles (optional, else assume DB data is correct)
        this.authorities = List.of(userInfo.getRoles().split(","))
                .stream()
                .map(String::trim)
                // Optional: filter to allow only valid roles - uncomment if needed
                //.filter(role -> role.equals("ROLE_ADMIN") || role.equals("ROLE_USER") || role.equals("ROLE_SELLER"))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
