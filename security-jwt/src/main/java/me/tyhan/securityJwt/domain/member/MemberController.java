package me.tyhan.securityJwt.domain.member;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import me.tyhan.securityJwt.domain.member.entity.Member;
import me.tyhan.securityJwt.domain.member.entity.dto.MemberDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Api(tags = {"02. User"})
@RequiredArgsConstructor
@RestController
@RequestMapping("/member")
public class MemberController {
    private final MemberService memberService;

    @ApiOperation(value = "회원 가입")
    @PostMapping(value = "/signup")
    public ResponseEntity<Member> signUp (@Valid @RequestBody MemberDto reqDto) {
        return ResponseEntity.ok(memberService.signUp(reqDto));
    }

    @ApiOperation(value = "회원 인증 조회")
    @GetMapping(value = "/memberauth")
    public ResponseEntity<Member> inquiryMemberAuth(@RequestParam String email) {
        return ResponseEntity.ok(memberService.inquiryMemberAuth(email).get());
    }

    @ApiOperation(value = "본인 인증 조회")
    @GetMapping(value = "/myauth")
    public ResponseEntity<Member> inquiryMyAuth() {
        return ResponseEntity.ok(memberService.inquiryMyAuth().get());
    }
}
