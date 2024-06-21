package com.example.OAuthjwt.controller;

import com.example.OAuthjwt.entity.RefreshEntity;
import com.example.OAuthjwt.jwt.JwtUtil;
import com.example.OAuthjwt.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    private final Long ACCESS_TOKEN_EXPIRE_LENGTH = 1000L*60*60; // 1시간
    private final Long REFRESH_TOKEN_EXPIRE_LENGTH = 1000L*60*60*24*7; // 7일

    // 아래의 내용은 서비스단으로 나누어 계층분리 시킬것.
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        //get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            System.out.println("cookie = " + cookie.getName());

            if (cookie.getName().equals("refresh")) {

                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {

            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        //expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException exception) {

            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        //토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {

            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        //DB에 저장되어 있는지 확인
        boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {

            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);
        String name = jwtUtil.getName(refresh);

        //make new JWT
        String newAccess = jwtUtil.createJwt("access", username, role, ACCESS_TOKEN_EXPIRE_LENGTH, name);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, REFRESH_TOKEN_EXPIRE_LENGTH, name);

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username, newRefresh, 86400000L);

        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh));

        System.out.println("성공");
        return new ResponseEntity<>(HttpStatus.OK);
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
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
