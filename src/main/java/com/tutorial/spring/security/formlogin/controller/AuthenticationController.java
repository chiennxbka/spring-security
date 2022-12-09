package com.tutorial.spring.security.formlogin.controller;

import com.tutorial.spring.security.formlogin.config.jwt.JwtUtils;
import com.tutorial.spring.security.formlogin.model.Attempts;
import com.tutorial.spring.security.formlogin.model.User;
import com.tutorial.spring.security.formlogin.payload.LoginPayload;
import com.tutorial.spring.security.formlogin.payload.RegisterPayload;
import com.tutorial.spring.security.formlogin.repository.AttemptsRepository;
import com.tutorial.spring.security.formlogin.repository.UserRepository;
import com.tutorial.spring.security.formlogin.service.UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@Controller
public class AuthenticationController {

    @Autowired
    private UserService service;

    private static final int ATTEMPTS_LIMIT = 3;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AttemptsRepository attemptsRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/login")
    public String login(HttpServletRequest request, HttpSession session) {
        session.setAttribute("error", getErrorMessage(request));
        return "login";
    }

    @PostMapping("/login")
    @ResponseBody
    public String login(@RequestBody LoginPayload payload) {
        UserDetails userDetails;
        String username = payload.getUsername();
        String password = payload.getPassword();
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
            if (!userDetails.isAccountNonLocked()) {
                throw new BadCredentialsException("Account is locked!");
            }
            if (passwordEncoder.matches(password, userDetails.getPassword())) {
                // reset attempts = 0
                Optional<Attempts> attemptsUser = attemptsRepository.findByUsername(username);
                if (attemptsUser.isPresent()) {
                    Attempts attempts = attemptsUser.get();
                    attempts.setAttempts(0);
                    attemptsRepository.save(attempts);
                }
                // gen token voi subject la username va tra ve client
                return jwtUtils.generateJwtToken(username);
            } else {
                this.calculateAttempts(username);
                throw new BadCredentialsException("Invalid login details");
            }
        } catch (AuthenticationException exception) {
            throw new BadCredentialsException("Invalid login details");
        }
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth.isAuthenticated())
            new SecurityContextLogoutHandler().logout(request, response, auth);
        return "redirect:login";
    }

    @PostMapping("/register")
    public String register(@ModelAttribute RegisterPayload payload) {
        service.save(payload);
        return "redirect:login";
    }

    @GetMapping("/")
    public String home(HttpServletRequest request, HttpSession session) {
        return "home";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    private String getErrorMessage(HttpServletRequest request) {
        Exception exception = (Exception) request.getSession().getAttribute("SPRING_SECURITY_LAST_EXCEPTION");
        String error;
        if (exception instanceof BadCredentialsException) {
            error = "Invalid username and password!";
        } else if (exception instanceof LockedException) {
            error = exception.getMessage();
        } else {
            error = "Invalid username and password!";
        }
        return error;
    }

    private void calculateAttempts(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (user.isAccountNonLocked()) {
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
    }
}
