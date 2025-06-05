package com.ey.springboot3security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ey.springboot3security.entity.UserInfo;

@Repository
public interface UserInfoRepository extends JpaRepository<UserInfo, Integer> {

    // Used for login via email (username)
    Optional<UserInfo> findByEmail(String email);
}
