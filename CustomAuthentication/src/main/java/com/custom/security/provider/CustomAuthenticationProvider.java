package com.custom.security.provider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.custom.security.Authentication.CustomAuthentication;



@Component
public class CustomAuthenticationProvider implements AuthenticationProvider{
	
	@Value("${lol.lol.lol}")
	private String key;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		CustomAuthentication ca=(CustomAuthentication)authentication;
		if(ca.getKey().equals(key)) {
			return new CustomAuthentication(true, null);
		}
		throw new BadCredentialsException("Not valid credentials");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		
		return CustomAuthentication.class.equals(authentication);
	}

}
