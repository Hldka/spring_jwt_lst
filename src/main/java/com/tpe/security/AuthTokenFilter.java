package com.tpe.security;

import org.springframework.beans.factory.annotation.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.context.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Component;
import org.springframework.util.*;
import org.springframework.web.filter.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String jwtToken = parseJwt(request);

        try {
            if(jwtToken!=null && jwtUtils.validateToken(jwtToken)){

                String userName  = jwtUtils.getUserNameFromJwtToken(jwtToken);// securuty contex'e atabilmek icin
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                UsernamePasswordAuthenticationToken authentication =// springboot bize veriyor
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);//security contex'e göndermek icin

            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request,response);


    }

    private String parseJwt(HttpServletRequest request){
        String header =  request.getHeader("Authorization");
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")) {// value degerin icinde ifade varmi ?ve ne ile basladigini
            return header.substring(7);
        }
        return null;

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        return antPathMatcher.match("/register", request.getServletPath()) ||// kullanici securuty katmanina girmeden buraya girebilsin diye yaptik
                antPathMatcher.match("/login" , request.getServletPath());
    }
}
