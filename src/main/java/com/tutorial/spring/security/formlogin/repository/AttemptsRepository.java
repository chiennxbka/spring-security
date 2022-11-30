package com.tutorial.spring.security.formlogin.repository;

import com.tutorial.spring.security.formlogin.model.Attempts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AttemptsRepository extends JpaRepository<Attempts, Integer> {

    Optional<Attempts> findByUsername(String username);
}
