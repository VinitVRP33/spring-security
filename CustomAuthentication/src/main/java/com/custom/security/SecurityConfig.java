package com.custom.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.custom.security.filter.CustomAuthenticationFilter;

import lombok.AllArgsConstructor;

@Configuration
@AllArgsConstructor
public class SecurityConfig {
	
	private CustomAuthenticationFilter customAuthenticationFilter;

	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		return http
				.addFilterAt(customAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.authorizeHttpRequests((x)->x.anyRequest().authenticated())
				.build();
		
	}
}

