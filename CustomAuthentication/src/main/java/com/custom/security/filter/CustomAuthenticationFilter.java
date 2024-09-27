package com.custom.security.filter;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.custom.security.Authentication.CustomAuthentication;
import com.custom.security.manager.CustomManager;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@Component  
@AllArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter{
	
	private CustomManager customManager;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String headerKey=String.valueOf(request.getHeader("secretKey"));
		CustomAuthentication ca=new CustomAuthentication(false, headerKey);
		Authentication result = customManager.authenticate(ca);
		
		if(result.isAuthenticated()) {
			SecurityContextHolder.getContext().setAuthentication(result);
			filterChain.doFilter(request, response);
		}
				
	}
	

}
