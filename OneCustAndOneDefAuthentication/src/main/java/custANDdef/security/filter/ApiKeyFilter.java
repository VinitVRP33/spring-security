package custANDdef.security.filter;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import custANDdef.security.authentication.ApiKeyAuthentication;
import custANDdef.security.manager.ApiKeyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class ApiKeyFilter extends OncePerRequestFilter{
	
	private String key;
	 

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
	
		ApiKeyManager customManager=new ApiKeyManager(key);
		
		String userkey=request.getHeader("x-api-key");
		
		var v=new ApiKeyAuthentication(userkey,false);
		
		try {
			
			var checkedAuth=customManager.authenticate(v);
			if(checkedAuth.isAuthenticated()) {
				SecurityContextHolder.getContext().setAuthentication(checkedAuth);
				filterChain.doFilter(request, response);
			}else {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			}
			
		} catch (AuthenticationException e) {
			System.out.println("hello");
		}

		
		
		
	}

}
