package com.example.OAuthjwt.jwt;

import com.example.OAuthjwt.dto.CustomUserDetails;
import com.example.OAuthjwt.entity.RefreshEntity;
import com.example.OAuthjwt.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.bcel.Const;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    private final AuthenticationManager authenticationManager;

    private final Long ACCESS_TOKEN_EXPIRE_LENGTH = 1000L*60*60; // 1시간
    private final Long REFRESH_TOKEN_EXPIRE_LENGTH = 1000L*60*60*24*7; // 7일

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청해서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username = " + username);

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }

    //로그인 성공시 실행하는 메서드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        //유저 정보
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();
        //  임시 이름값 받아오기
        String name = customUserDetails.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        //토큰 생성
        String access = jwtUtil.createJwt("access", username, role, ACCESS_TOKEN_EXPIRE_LENGTH, name);
        String refresh = jwtUtil.createJwt("refresh", username, role, REFRESH_TOKEN_EXPIRE_LENGTH, name);

        //refresh 토근 저장
        addRefreshEntity(username, refresh, REFRESH_TOKEN_EXPIRE_LENGTH);

        //응답 설정
        response.addHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }


    //로그인 실패시 실행하는 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        //로그인 실패시 401 응답 코드 반환
        response.setStatus(401);
    }
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = RefreshEntity.builder()
                .username(username)
                .refresh(refresh)
                .expired(date.toString())
                .build();

        refreshRepository.save(refreshEntity);
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(REFRESH_TOKEN_EXPIRE_LENGTH.intValue());
//        cookie.setSecure(true);
//        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}

// 단일 JWT
    //로그인 성공시 실행하는 메서드 (여기서 JWT를 발급하면 됨)
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
//
//        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
//
//        String username = customUserDetails.getUsername();
//
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//
//        String role = auth.getAuthority();
//
//        String token = jwtUtil.createJwt(username, role, 60*60*10L);
//
//        response.addHeader("Authorization", "Bearer " + token);
//    }