package custANDdef.security.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import custANDdef.security.authentication.ApiKeyAuthentication;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class ApiKeyProvider implements AuthenticationProvider{
	
	private String key;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		ApiKeyAuthentication apiKeyAuthentication=(ApiKeyAuthentication)authentication;
		if(key.equals(apiKeyAuthentication.getKey())) {
			apiKeyAuthentication.setAuthenticated(true);
			return apiKeyAuthentication;
		}
	throw new BadCredentialsException("Bad credentials sir");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		
		return ApiKeyAuthentication.class.equals(authentication);
	}

}
