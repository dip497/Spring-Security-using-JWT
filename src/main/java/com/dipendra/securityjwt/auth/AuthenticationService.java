package com.dipendra.securityjwt.auth;

import com.dipendra.securityjwt.config.JwtService;
import com.dipendra.securityjwt.entity.Role;
import com.dipendra.securityjwt.entity.TokenType;
import com.dipendra.securityjwt.entity.Tokens;
import com.dipendra.securityjwt.entity.Users;
import com.dipendra.securityjwt.repository.TokenRepository;
import com.dipendra.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;

    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(
            RegisterRequest request
    ) {
        var user = Users.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        var savedUser = repository.save(user);

        var jwtToken = jwtService.
                generateToken(user);

        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(
            AuthenticationRequest request
    ) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository
                .findByEmail(request.getEmail())
                .orElseThrow();

        var jwtToken = jwtService
                .generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);

        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }

    private void revokeAllUserTokens(Users user){
        var validUserToken = tokenRepository.findAllValidTokensByUser(user.getId());
        if(validUserToken.isEmpty()){
            return;
        }
        validUserToken.forEach(t ->{
            t.setExpired(true);
            t.setRevoked(true);
        });

        tokenRepository.saveAll(validUserToken);


    }

    private void saveUserToken(Users user, String jwtToken) {
        var token = Tokens.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepository.save(token);
    }
}
