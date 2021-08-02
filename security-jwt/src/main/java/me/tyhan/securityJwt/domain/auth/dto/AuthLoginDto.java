package me.tyhan.securityJwt.domain.auth.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@NoArgsConstructor
@Getter
@Setter
public class AuthLoginDto {

    @NotNull
    private String email;

    @NotNull
    private String password;

//    private Integer provider;
}
