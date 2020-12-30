//package com.auth.config.handler;
//
//import java.util.Arrays;
//
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//
//import org.springframework.beans.factory.annotation.Qualifier;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.HttpEntity;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.ResponseEntity;
//import org.springframework.http.converter.FormHttpMessageConverter;
//import org.springframework.http.converter.HttpMessageConverter;
//import org.springframework.http.converter.StringHttpMessageConverter;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
//import org.springframework.security.web.authentication.logout.LogoutHandler;
//import org.springframework.stereotype.Component;
//import org.springframework.util.LinkedMultiValueMap;
//import org.springframework.util.MultiValueMap;
//import org.springframework.web.client.HttpClientErrorException;
//import org.springframework.web.client.RestTemplate;
//
////@Slf4j
//@Component
//@Qualifier("mySsoLogoutHandler")
//public class MySsoLogoutHandler implements LogoutHandler {
//
//    @Value("${my.oauth.server.schema}://${my.oauth.server.host}:${my.oauth.server.port}/invalidateToken")
//    String logoutUrl;
//
//    @Override
//    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
//
//    	Authentication authentication2 = SecurityContextHolder.getContext().getAuthentication();
//    	System.out.println(authentication2);
////        LOGGER.debug("executing MySsoLogoutHandler.logout");
//        Object details = authentication.getDetails();
//        if (details.getClass().isAssignableFrom(OAuth2AuthenticationDetails.class)) {
//
//            String accessToken = ((OAuth2AuthenticationDetails)details).getTokenValue();
////            LOGGER.debug("token: {}",accessToken);
//
//            RestTemplate restTemplate = new RestTemplate();
//
//            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
//            params.add("accessToken", accessToken);
//
//            HttpHeaders headers = new HttpHeaders();
//            headers.add("Authorization", "bearer " + accessToken);
//
//            HttpEntity<String> request = new HttpEntity(params, headers);
//
//            HttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
//            HttpMessageConverter stringHttpMessageConverternew = new StringHttpMessageConverter();
//            restTemplate.setMessageConverters(Arrays.asList(new HttpMessageConverter[]{formHttpMessageConverter, stringHttpMessageConverternew}));
//            try {
//                ResponseEntity<String> response = restTemplate.exchange(logoutUrl, HttpMethod.POST, request, String.class);
//            } catch(HttpClientErrorException e) {
////                LOGGER.error("HttpClientErrorException invalidating token with SSO authorization server. response.status code: {}, server URL: {}", e.getStatusCode(), logoutUrl);
//            }
//        }
//
//
//    }
//}