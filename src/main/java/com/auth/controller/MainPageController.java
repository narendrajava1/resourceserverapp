package com.auth.controller;

import java.security.Principal;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api")
public class MainPageController {

	@Value("${my.oauth.server.schema}://${my.oauth.server.host}:${my.oauth.server.port}/security/invalidateToken")
    String logoutUrl;

    @GetMapping("/main")
    public String main(Principal principal) {
    	String name = principal.getName();
    	return name;
    }
    
    @GetMapping("/get-welcome-message-all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public String getWelcomeMsgForAll() {
		return "Hi All, Welcome to access the Protected Resourcessss!!!";
	}
    
//    @GetMapping(value = "/oauth/logout")
//    public ResponseEntity<String> logout(@RequestParam(name = "access_token") String accessToken) {
//        consumerTokenServices.revokeToken(accessToken);
////        return new ResponseEntity<>(new Response(messageSource.getMessage("server.message.oauth.logout.successMessage",  null, LocaleContextHolder.getLocale())), HttpStatus.OK);
//		return new ResponseEntity<>("LogOtSuccsFully",HttpStatus.OK);
//
//    }
    
    
//    @Override
    @GetMapping(value = "/logout")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> logout(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse,Authentication auth) {
        Object details = auth.getDetails();
        if (details.getClass().isAssignableFrom(OAuth2AuthenticationDetails.class)) {

            String accessToken = ((OAuth2AuthenticationDetails)details).getTokenValue();
//            LOGGER.debug("token: {}",accessToken);

            RestTemplate restTemplate = new RestTemplate();

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("accessToken", accessToken);

            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "bearer " + accessToken);

            HttpEntity<String> request = new HttpEntity(params, headers);

            HttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
            HttpMessageConverter stringHttpMessageConverternew = new StringHttpMessageConverter();
            restTemplate.setMessageConverters(Arrays.asList(new HttpMessageConverter[]{formHttpMessageConverter, stringHttpMessageConverternew}));
            try {
                ResponseEntity<String> response = restTemplate.exchange(logoutUrl, HttpMethod.POST, request, String.class);
            } catch(HttpClientErrorException e) {
//                LOGGER.error("HttpClientErrorException invalidating token with SSO authorization server. response.status code: {}, server URL: {}", e.getStatusCode(), logoutUrl);
            }
//        if (auth != null){
//            new SecurityContextLogoutHandler().logout(request, response, auth);
//        }

        return new ResponseEntity<>("Logout Succssfull done!", HttpStatus.OK);
    }
		return null;
    }
}