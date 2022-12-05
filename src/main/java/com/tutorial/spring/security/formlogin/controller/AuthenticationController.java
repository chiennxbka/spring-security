package com.tutorial.spring.security.formlogin.controller;

import com.tutorial.spring.security.formlogin.model.User;
import com.tutorial.spring.security.formlogin.payload.RegisterPayload;
import com.tutorial.spring.security.formlogin.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Controller
public class AuthenticationController {

    @Autowired private UserService service;

    @GetMapping("/login")
    public String login(HttpServletRequest request, HttpSession session) {
        session.setAttribute("error", getErrorMessage(request));
        return "login";
    }

   /* @GetMapping("/logout")
    public String logout() {
        return "redirect:login";
    }*/

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
}
