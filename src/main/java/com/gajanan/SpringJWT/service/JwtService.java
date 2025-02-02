package com.gajanan.SpringJWT.service;

import com.gajanan.SpringJWT.model.User;
import com.gajanan.SpringJWT.repo.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final TokenRepository tokenRepository;

    @Value("${spring.application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${spring.application.security.jwt.access-token-expiration}")
    private long accessTokenExpire;

    @Value("${spring.application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    public JwtService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public String generateAccessToken(User user) {
//        String token= Jwts.builder()
//                .subject(user.getUserName())
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
//                .signWith(getSigninkey())
//                .compact();
//
//        return token;

        return generateToken(user, accessTokenExpire); // 86400000
    }

    public String generateRefreshToken(User user) { // refresh token valid for 7 days
//        String token= Jwts.builder()
//                .subject(user.getUserName())
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis() + 7*24*60*60*1000))
//                .signWith(getSigninkey())
//                .compact();
//
//        return token;

        return generateToken(user, refreshTokenExpire); // 604800000
    }

    private String generateToken(User user,long expiredTime) {
        String token= Jwts.builder()
                .subject(user.getUserName())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredTime))
                .signWith(getSigninkey())
                .compact();

        return token;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> resolver){
        Claims claims=extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninkey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }

    private SecretKey getSigninkey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean validateAccessToken(String token, UserDetails userDetails) {
        String username=extractUsername(token);

        boolean isValidAccessToken =tokenRepository.findByAccessToken(token).map(t->!t.isLoggedOut()).orElse(false);

        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token) && isValidAccessToken);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean ValidateRefreshToken(String token, User user) {
        String userName=extractUsername(token);

        boolean isValidRefreshToken=tokenRepository.findByRefreshToken(token).map(t->!t.isLoggedOut()).orElse(false);

        return (userName.equals(user.getUserName()) && !isTokenExpired(token) && isValidRefreshToken);
    }
}
