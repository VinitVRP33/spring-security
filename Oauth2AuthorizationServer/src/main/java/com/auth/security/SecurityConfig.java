package com.auth.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.auth.customValidator.CustomRedirectUriValidator;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class SecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
		
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		
		http
		.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
		.authorizationEndpoint(
				a->a.authenticationProviders(getAuthenticatorProviders())
		)
		.oidc(Customizer.withDefaults());
		
		http.exceptionHandling(v->v
				.authenticationEntryPoint(
						new LoginUrlAuthenticationEntryPoint("/login")
					)
				);
		
		return http
				.build();
	}
	
	private Consumer<List<AuthenticationProvider>> getAuthenticatorProviders() {
		
		return providers->{
			for(AuthenticationProvider provider : providers) {
				if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider v) {
					v.setAuthenticationValidator(new CustomRedirectUriValidator());
					
				}
		}	
			
	};
}

	@Bean
	@Order(2)
	public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
		
		
		
		return http
				.formLogin(Customizer.withDefaults())
				.authorizeHttpRequests(x->x
				.anyRequest().authenticated())
				.build();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
		var uds=new InMemoryUserDetailsManager();
		
		var user1=User
				.withUsername("Vinit")
				.password("777")
				.authorities("read","write")
				.build();
		
		var user2=User
				.withUsername("Bhargav")
				.password("999")
				.authorities("delete")
				.build();
		
		uds.createUser(user1);
		uds.createUser(user2);
		
		return uds;
	
	}
	
	@Bean
	public RegisteredClientRepository clientRepository() {
		
		RegisteredClient c1=RegisteredClient
				.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientName("Google")
				.clientSecret("secret")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.redirectUri("https://springone.io/authorized")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.tokenSettings(
						TokenSettings.builder()
						.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
						.accessTokenTimeToLive(Duration.ofSeconds(700))
						.build()
						)   
				.build();
		
		return new InMemoryRegisteredClientRepository(c1);
					
	}
	
	/*Here tokenFormat is reference which means the token it will generate will be opaque token that is it will not 
	 contain any data and you can fetch it using introspection endpoint and if we use the self_contained that means a 
	 it will give the non  opaque token that means it will contain data in it (JWT)
	*/
	
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		
		return AuthorizationServerSettings
				.builder()
				.build();
		
	}
	
	@Bean
	public JWKSource<SecurityContext> keySource() throws NoSuchAlgorithmException{
		
		KeyPairGenerator kpg=KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp=kpg.generateKeyPair();
		
		RSAPublicKey publicKey=(RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey=(RSAPrivateKey)kp.getPrivate();
		
		RSAKey rsaKey=new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		
		JWKSet set=new JWKSet(rsaKey);
		return new ImmutableJWKSet(set);
		
		
	}
	
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenConfigure(){
		
		return context->{
			context.getClaims().claim("name", "Vinit");
			
		};
	}
	
}
