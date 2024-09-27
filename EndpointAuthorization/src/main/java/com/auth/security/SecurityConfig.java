package com.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		return http
				.httpBasic(x->x.init(http))
				.authorizeHttpRequests(x->x
				//.anyRequest().authenticated()
				//.anyRequest().permitAll()
				//.anyRequest().denyAll()
				//.anyRequest().hasAuthority("read")
				//.anyRequest().hasAnyAuthority("read","write")
				//.anyRequest().hasRole("MANAGER")
				//.anyRequest().hasAnyRole("MANAGER","ADMIN")
				//.anyRequest().access(null)
				.requestMatchers(HttpMethod.GET,"/demo/**").hasAuthority("read")
				)
				.build();
		
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
		var uds = new InMemoryUserDetailsManager();
		
		var user1=User
				.withUsername("Laur")
				.password(passwordEncoder().encode("99977"))
				//.roles("ADMIN") //equivalent to authorities("ROLE_ADMIN")
				.authorities("read")
				.build();
		
		var user2=User
				.withUsername("Vinit")
				.password(passwordEncoder().encode("77777"))
				.authorities("ROLE_MANAGER","write") //equivalent to roles("ADMIN")
				//.authorities("write")
				.build();

		//Can only use .roles() or .authorities() here not both together
		
		uds.createUser(user1);
		uds.createUser(user2);
		
		return uds;
	}

}
