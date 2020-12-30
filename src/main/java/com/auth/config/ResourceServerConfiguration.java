package com.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(proxyTargetClass = true, prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

//	@Autowired
//	MySsoLogoutHandler mySsoLogoutHandler;


	@Autowired
	private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

		resources.resourceId("api-resource");
		resources.authenticationEntryPoint(customAuthenticationEntryPoint);

	}
	
	

	@Override
	public void configure(HttpSecurity http) throws Exception {
//		http
//		.logout().clearAuthentication(false) 
//		.logoutSuccessUrl("/")
//		// using this antmatcher allows /logout from GET without csrf as indicated in
//        // https://docs.spring.io/spring-security/site/docs/current/reference/html/csrf.html#csrf-logout
//        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//        // this LogoutHandler invalidate user token from SSO
//        .addLogoutHandler(mySsoLogoutHandler);
		http.exceptionHandling().authenticationEntryPoint(customAuthenticationEntryPoint);
		http.authorizeRequests().antMatchers("/api/main")
		.hasRole("USER").anyRequest().authenticated();
	}

	@Primary
	@Bean
	public RemoteTokenServices tokenService() {
		RemoteTokenServices tokenService = new RemoteTokenServices();
		tokenService.setCheckTokenEndpointUrl("http://localhost:8080/oauth/check_token");
		tokenService.setClientId("way2learnappclientid");
		tokenService.setClientSecret("secret");
		return tokenService;
	}

}
