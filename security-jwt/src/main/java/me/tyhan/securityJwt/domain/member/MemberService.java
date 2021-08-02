package me.tyhan.securityJwt.domain.member;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.tyhan.securityJwt.domain.member.entity.Member;
import me.tyhan.securityJwt.domain.member.entity.MemberRepository;
import me.tyhan.securityJwt.domain.member.entity.Role;
import me.tyhan.securityJwt.domain.member.entity.dto.MemberDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public Member signUp(MemberDto reqDto) {
        if (memberRepository.findByEmail(reqDto.getEmail()).isPresent()) {
            throw new RuntimeException("이미 존재하는 이메일.");
        }

        Role role = Role.builder().id(2L).build();

        Member member = Member.builder()
                .email(reqDto.getEmail())
                .password(passwordEncoder.encode(reqDto.getPassword()))
                .name(reqDto.getName())
                .roles(Collections.singleton(role))
                .build();

        return memberRepository.save(member);
    }

    public Optional<Member> inquiryMemberAuth(String email) {
        return memberRepository.findByEmail(email);
    }

    public Optional<Member> inquiryMyAuth() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            log.debug("Security Context에 인증 정보 없음.");
            return Optional.empty();
        }

        String email = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            UserDetails springSecurityUser = (UserDetails)authentication.getPrincipal();
            email = springSecurityUser.getUsername();
        } else if (authentication.getPrincipal() instanceof String) {
            email = (String)authentication.getPrincipal();
        }

        return memberRepository.findByEmail(email);
    }
}
