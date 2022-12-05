package com.tutorial.spring.security.formlogin.config;

import com.tutorial.spring.security.formlogin.model.Attempts;
import com.tutorial.spring.security.formlogin.model.User;
import com.tutorial.spring.security.formlogin.repository.AttemptsRepository;
import com.tutorial.spring.security.formlogin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class AuthProvider implements AuthenticationProvider {

    private static final int ATTEMPTS_LIMIT = 3;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AttemptsRepository attemptsRepository;

    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) {
        String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDER" : authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
            if (passwordEncoder.matches(password, userDetails.getPassword())) {
                return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
            } else {
                this.calculateAttempts(username);
                throw new BadCredentialsException("Invalid login details");
            }
        } catch (AuthenticationException exception) {
            throw new BadCredentialsException("Invalid login details");
        }
    }

    private void calculateAttempts(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            Optional<Attempts> attemptsUser = attemptsRepository.findByUsername(username);
            if (attemptsUser.isPresent()) {
                Attempts attempts = attemptsUser.get();
                if (attempts.getAttempts() + 1 >= ATTEMPTS_LIMIT) {
                    attempts.setAttempts(attempts.getAttempts() + 1);
                    attemptsRepository.save(attempts);
                    user.setAccountNonLocked(false);
                    userRepository.save(user);
                }
                attempts.setAttempts(attempts.getAttempts() + 1);
                attemptsRepository.save(attempts);
            } else {
                attemptsRepository.save(new Attempts(username, 1));
            }
        }
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return authenticationType.equals(UsernamePasswordAuthenticationToken.class);
    }
}
