package com.userserver;


import com.userserver.domain.service.JwtTokenService;
import com.userserver.domain.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.tomcat.util.buf.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class CustomFilter extends OncePerRequestFilter {

    private JwtTokenService jwtTokenService;
    private UserService userService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        var bearer = request.getHeader("Authorization");
        String jwt;
        String email;
        if(bearer == null && !bearer.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
        }

        jwt = bearer.substring(7);
        email = jwtTokenService.getSubject(jwt);

        if(!email.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userService.userDetailsService().loadUserByUsername(email);
            if(!jwtTokenService.isInvalid(jwt)){
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                context.setAuthentication(authenticationToken);
                SecurityContextHolder.setContext(context);
            }
        }
        filterChain.doFilter(request,response);

    }
}
