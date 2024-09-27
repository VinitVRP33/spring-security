package custANDdef.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import custANDdef.security.filter.ApiKeyFilter;

@Configuration
public class SecurityConfig {
	
	@Value("${lol.lol}")
	private String key;
	


	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		System.out.println("Hii");
		
		return http
				.httpBasic(x->x.init(http))
				.addFilterBefore(new ApiKeyFilter(key), BasicAuthenticationFilter.class)
				.authorizeHttpRequests(x->x.anyRequest().authenticated())
				.build();
	}
}
