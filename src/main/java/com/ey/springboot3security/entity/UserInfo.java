package com.ey.springboot3security.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "user_info") // Database table name
public class UserInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email; // Used as username for login

    @Column(nullable = false)
    private String password; // Encrypted using BCrypt

    @Column(nullable = false)
    private String roles; // Comma-separated roles: ROLE_USER,ROLE_ADMIN,ROLE_SELLER

    // No-arg constructor
    public UserInfo() {}

    // All-args constructor
    public UserInfo(int id, String name, String email, String password, String roles) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }

    // Getters and setters

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    // Required for Spring Security
    public String getUsername() {
        return this.email;
    }
}
