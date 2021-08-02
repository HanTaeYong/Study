package me.tyhan.securityJwt.domain.member.entity.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@NoArgsConstructor
@Setter
@Getter
public class MemberDto {

    @NotNull
    private String email;

    @NotNull
    private String name;

    @NotNull
    private String password;

}
