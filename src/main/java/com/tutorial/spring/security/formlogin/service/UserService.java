package com.tutorial.spring.security.formlogin.service;

import com.tutorial.spring.security.formlogin.payload.RegisterPayload;

public interface UserService {
    void save(RegisterPayload payload);
}
