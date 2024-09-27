package com.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		return http
				.httpBasic(Customizer.withDefaults())
				.authorizeHttpRequests(x->x
				.anyRequest().authenticated())
				.build();
		
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
		var uds=new InMemoryUserDetailsManager();
		
		var user1=User
				.withUsername("Vinit")
				.password(passwordEncoder().encode("777"))
				.authorities("read","write")
				.build();
		
		var user2=User
				.withUsername("Bhargav")
				.password(passwordEncoder().encode("999"))
				.authorities("delete")
				.build();
		
		uds.createUser(user1);
		uds.createUser(user2);
		
		return uds;
	}

}
