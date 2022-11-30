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
    private AttemptsRepository attemptsRepository;

    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDER" : authentication.getName();
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (BadCredentialsException exception) {
            this.calculateAttempts(username);
            throw new BadCredentialsException("Invalid login details");
        }
        return this.createSuccessfulAuthentication(authentication, userDetails);
    }

    private void calculateAttempts(String username) {
        Optional<Attempts> userAttempts = attemptsRepository.findByUsername(username);
        if (userAttempts.isPresent()) {
            Attempts attempts = userAttempts.get();
            if (attempts.getAttempts() + 1 >= ATTEMPTS_LIMIT) {
                attempts.setAttempts(attempts.getAttempts() + 1);
                attemptsRepository.save(attempts);
                User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User name not found"));
                user.setAccountNonLocked(false);
                userRepository.save(user);
                throw new LockedException("Too many invalid attempts. Account is locked!!");
            }
            attempts.setAttempts(attempts.getAttempts() + 1);
            attemptsRepository.save(attempts);
        }
    }

    private Authentication createSuccessfulAuthentication(final Authentication authentication, final UserDetails user) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), authentication.getCredentials(), user.getAuthorities());
        token.setDetails(authentication.getDetails());
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
