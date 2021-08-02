package me.tyhan.securityJwt.common.service;

import lombok.RequiredArgsConstructor;
import me.tyhan.securityJwt.domain.member.entity.Member;
import me.tyhan.securityJwt.domain.member.entity.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class MemberDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(final String username) {
        return memberRepository.findOneWithRolesByEmail(username)
                .map(member -> createUser(username, member))
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> DB에서 찾을 수 없음."));
    }

    private org.springframework.security.core.userdetails.User createUser(String email, Member member) {
        List<GrantedAuthority> grantedAuthorities = member.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleCode()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
                member.getEmail(), member.getPassword(), grantedAuthorities
        );
    }
}
