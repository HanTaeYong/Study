package me.tyhan.securityJwt.domain.auth.dto;

import lombok.*;

import javax.validation.constraints.NotNull;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthLoginResDto {

    private String accessToken;

    private Long id;

    private String roles;

    private String name;
}
