package com.custom.security.manager;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.custom.security.provider.CustomAuthenticationProvider;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class CustomManager implements AuthenticationManager{
	
	private CustomAuthenticationProvider customAuthenticationProvider;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	
		if(customAuthenticationProvider.supports(authentication.getClass())){
			return customAuthenticationProvider.authenticate(authentication);
			
		}
		
		throw new BadCredentialsException("OH NO");
	}
	

}
