package com.gajanan.SpringJWT.service;

import com.gajanan.SpringJWT.model.AuthenticationResponse;
import com.gajanan.SpringJWT.model.Token;
import com.gajanan.SpringJWT.model.User;
import com.gajanan.SpringJWT.repo.TokenRepository;
import com.gajanan.SpringJWT.repo.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

        String accessToken=jwtService.generateAccessToken(user);
        String refreshToken=jwtService.generateRefreshToken(user);

        // save the token in database
        saveUserToken(accessToken, refreshToken, user);

        return new AuthenticationResponse(accessToken,refreshToken);

    }


    public AuthenticationResponse login(User request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUserName(),request.getPassword()
                )
        );

        User user=userRepository.findByUserName(request.getUserName()).orElseThrow(()->new UsernameNotFoundException("user not found"));
        String accessToken=jwtService.generateAccessToken(user);
        String refreshToken=jwtService.generateRefreshToken(user);

        revokeAllTokenByUser(user);

        saveUserToken(accessToken, refreshToken, user);

        return new AuthenticationResponse(accessToken,refreshToken);

    }

    private void saveUserToken(String accessToken,String refreshToken, User user) {
        Token token1=new Token();
        token1.setAccessToken(accessToken);
        token1.setRefreshToken(refreshToken);
        token1.setLoggedOut(false);
        token1.setUser(user);
        tokenRepository.save(token1);
    }

    private void revokeAllTokenByUser(User user) {
        List<Token> validTokenListByUser=tokenRepository.findAllAccessTokenByUserId(user.getId());

        if(!validTokenListByUser.isEmpty()){
            validTokenListByUser.forEach(t-> t.setLoggedOut(true));
        }
        tokenRepository.saveAll(validTokenListByUser);
    }

    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {

        // extract the token from the authorization header
        String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        String token=authHeader.substring(7);

        // extract the username from the token
        String username=jwtService.extractUsername(token);

        // check if the user is existed in the database
        User user=userRepository.findByUserName(username)
                .orElseThrow(()->new UsernameNotFoundException("user not found"));

        // now check if refresh token is valid
        if(jwtService.ValidateRefreshToken(token,user)){
            // generate access token
            String accessToken=jwtService.generateAccessToken(user);
            String refreshToken=jwtService.generateRefreshToken(user);

            revokeAllTokenByUser(user);

            saveUserToken(accessToken, refreshToken, user);

            return new ResponseEntity(new AuthenticationResponse(accessToken,refreshToken),HttpStatus.OK);

        }
        return new ResponseEntity(HttpStatus.UNAUTHORIZED);
    }
}
