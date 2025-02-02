package com.gajanan.SpringJWT.service;

import com.gajanan.SpringJWT.model.AuthenticationResponse;
import com.gajanan.SpringJWT.model.Token;
import com.gajanan.SpringJWT.model.User;
import com.gajanan.SpringJWT.repo.TokenRepository;
import com.gajanan.SpringJWT.repo.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, TokenRepository tokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.tokenRepository = tokenRepository;
    }

    public AuthenticationResponse register(User request){
        User newUser = new User();
        newUser.setFirstName(request.getFirstName());
        newUser.setLastName(request.getLastName());
        newUser.setUserName(request.getUserName());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRole(request.getRole());

        User user = userRepository.save(newUser);

        String token=jwtService.generateToken(user);

        // save the token in database
        saveUserToken(token, user);

        return new AuthenticationResponse(token);

    }


    public AuthenticationResponse login(User request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUserName(),request.getPassword()
                )
        );

        User user=userRepository.findByUserName(request.getUserName()).orElseThrow();
        String token=jwtService.generateToken(user);

        revokeAllTokenByUser(user);

        saveUserToken(token, user);

        return new AuthenticationResponse(token);

    }

    private void saveUserToken(String token, User user) {
        Token token1=new Token();
        token1.setToken(token);
        token1.setLoggedOut(false);
        token1.setUser(user);
        tokenRepository.save(token1);
    }

    private void revokeAllTokenByUser(User user) {
        List<Token> validTokenListByUser=tokenRepository.findAllTokenByUserId(user.getId());

        if(!validTokenListByUser.isEmpty()){
            validTokenListByUser.forEach(t-> t.setLoggedOut(true));
        }
        tokenRepository.saveAll(validTokenListByUser);
    }
}
