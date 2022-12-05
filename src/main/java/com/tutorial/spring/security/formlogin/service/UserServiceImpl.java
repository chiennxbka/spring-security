package com.tutorial.spring.security.formlogin.service;

import com.tutorial.spring.security.formlogin.model.User;
import com.tutorial.spring.security.formlogin.payload.RegisterPayload;
import com.tutorial.spring.security.formlogin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    @Autowired private UserRepository repository;

    @Autowired private PasswordEncoder encoder;

    @Override
    public void save(RegisterPayload payload) {
        User user = new User(payload.getUsername(), encoder.encode(payload.getPassword()), true);
        repository.save(user);
    }
}
