package com.auth.customValidator;

import java.util.function.Consumer;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>{

	@Override
	public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext t) {
		
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = t.getAuthentication();
		RegisteredClient client = t.getRegisteredClient();
		String redirectUri = authentication.getRedirectUri();
		
		if(!client.getRedirectUris().contains(redirectUri)) {
			var error=new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
		}
	}

	
}
