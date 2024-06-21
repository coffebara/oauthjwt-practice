package com.example.OAuthjwt.controller;

import com.example.OAuthjwt.dto.CustomUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collection;
import java.util.Iterator;

@ResponseBody
@Controller
public class MainController {

    @GetMapping("/")
    public String mainP() {

        // username 가져오기
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        //roll 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        String role = auth.getAuthority();

        //name 가져오기
        CustomUserDetails custom = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String name = custom.getName();


        return "Main Controller : "+ username + name + role;
    }
}
