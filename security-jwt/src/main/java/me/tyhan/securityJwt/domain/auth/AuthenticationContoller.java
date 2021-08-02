package me.tyhan.securityJwt.domain.auth;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import me.tyhan.securityJwt.common.security.JwtAuthenticationFilter;
import me.tyhan.securityJwt.common.security.JwtTokenProvider;
import me.tyhan.securityJwt.domain.auth.dto.AuthLoginDto;
import me.tyhan.securityJwt.domain.auth.dto.AuthLoginResDto;
import me.tyhan.securityJwt.domain.member.entity.Member;
import me.tyhan.securityJwt.domain.member.entity.MemberRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@Api(tags = {"01. 인증"})
@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthenticationContoller {

    private final AuthenticationService authenticationService;

    @ApiOperation(value = "로그인")
    @PostMapping(value = "/login")
    public ResponseEntity<AuthLoginResDto> login(@Valid @RequestBody AuthLoginDto reqDto) {
        AuthLoginResDto resDto = authenticationService.login(reqDto);

//        HttpHeaders httpHeaders = new HttpHeaders();
//        httpHeaders.add(JwtTokenProvider.AUTHORIZATION_HEADER, "Bearer " + resDto.getAccessToken());

//        return new ResponseEntity<>(resDto, httpHeaders, HttpStatus.OK);
        return ResponseEntity.ok(resDto);
    }

//    @ApiOperation(value = "로그인")
//    @PostMapping(value = "/login")
//    public ResponseEntity<AuthLoginResDto> login(@Valid @RequestBody AuthLoginDto reqDto) {
//
//        Member member = memberRepository.findByEmail(reqDto.getEmail()).orElseThrow(() -> new RuntimeException("Not fount email."));
//        if (!passwordEncoder.matches(reqDto.getPassword(), member.getPassword())) {
//            throw new RuntimeException("password incorrect.");
//        }
//
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(reqDto.getEmail(), reqDto.getPassword());
//
//        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        String token = jwtTokenProvider.createToken(authentication);
//        HttpHeaders httpHeaders = new HttpHeaders();
//        httpHeaders.add(JwtAuthenticationFilter.AUTHORIZATION_HEADER, "Bearer " + token);
////        AuthLoginResDto authLoginResDto = AuthLoginResDto.builder()
////                .accessToken(token)
////                .id(member.getId())
////                .name(member.getName())
////                .roles(String.valueOf(member.getRoles()))
////                .build();
//
//        return new ResponseEntity<>(new AuthLoginResDto(token), httpHeaders, HttpStatus.OK);
//    }
}
