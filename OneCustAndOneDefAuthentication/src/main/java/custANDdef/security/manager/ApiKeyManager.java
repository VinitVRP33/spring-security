package custANDdef.security.manager;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import custANDdef.security.provider.ApiKeyProvider;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class ApiKeyManager implements AuthenticationManager{
	
	private String key;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		ApiKeyProvider apiKeyProvider=new ApiKeyProvider(key);
		if(apiKeyProvider.supports(authentication.getClass())) {
			return apiKeyProvider.authenticate(authentication);
			
		}
		return authentication;
	}

}
