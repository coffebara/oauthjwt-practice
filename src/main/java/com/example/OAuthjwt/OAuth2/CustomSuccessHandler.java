package com.example.OAuthjwt.OAuth2;

import com.example.OAuthjwt.dto.CustomOAuth2User;
import com.example.OAuthjwt.entity.RefreshEntity;
import com.example.OAuthjwt.jwt.JwtUtil;
import com.example.OAuthjwt.repository.RefreshRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    private final Long REFRESH_TOKEN_EXPIRE_LENGTH = 1000L*60*60*24*7; // 7일


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();
        //  임시 이름값 받아오기
        String name = customUserDetails.getName();


        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        //refresh 토큰 생성
        String refresh = jwtUtil.createJwt("refresh", username, role, REFRESH_TOKEN_EXPIRE_LENGTH, name);

        //refresh 토큰 저장
        addRefreshEntity(username, refresh, REFRESH_TOKEN_EXPIRE_LENGTH);


        response.addCookie(createCookie("refresh", refresh));
        response.sendRedirect("http://localhost:3000/");

    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(REFRESH_TOKEN_EXPIRE_LENGTH.intValue());
//        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
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
}
