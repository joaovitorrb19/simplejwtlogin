package com.userserver.domain.service;

import com.userserver.domain.entity.UserLoginDTO;
import com.userserver.domain.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtTokenService jwtTokenService;
    @Autowired
    private AuthenticationManager authenticationManager;

    public String login(UserLoginDTO userLoginDTO){
        this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLoginDTO.getEmail(),userLoginDTO.getPassword()));

        var user = this.userRepository.findByEmail(userLoginDTO.getEmail()).orElseThrow(() -> new IllegalArgumentException("Email invalido"));

        var jwt = this.jwtTokenService.createToken(user);

        return jwt;
    }

}
