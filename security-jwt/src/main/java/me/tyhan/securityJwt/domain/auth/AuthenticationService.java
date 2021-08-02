package me.tyhan.securityJwt.domain.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.tyhan.securityJwt.common.security.JwtAuthenticationFilter;
import me.tyhan.securityJwt.common.security.JwtTokenProvider;
import me.tyhan.securityJwt.domain.auth.dto.AuthLoginDto;
import me.tyhan.securityJwt.domain.auth.dto.AuthLoginResDto;
import me.tyhan.securityJwt.domain.member.entity.Member;
import me.tyhan.securityJwt.domain.member.entity.MemberRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.validation.Valid;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final PasswordEncoder passwordEncoder;

    public AuthLoginResDto login(@Valid @RequestBody AuthLoginDto reqDto) {

        Member member = memberRepository.findByEmail(reqDto.getEmail()).orElseThrow(() -> new RuntimeException("Not fount email."));
        if (!passwordEncoder.matches(reqDto.getPassword(), member.getPassword())) {
            throw new RuntimeException("password incorrect.");
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(reqDto.getEmail(), reqDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtTokenProvider.createToken(authentication);
//        HttpHeaders httpHeaders = new HttpHeaders();
//        httpHeaders.add(JwtAuthenticationFilter.AUTHORIZATION_HEADER, token);

        AuthLoginResDto authLoginResDto = AuthLoginResDto.builder()
                .accessToken(token)
                .id(member.getId())
                .name(member.getName())
                .roles(member.getRolesToString())
                .build();

        return authLoginResDto;
    }
}
