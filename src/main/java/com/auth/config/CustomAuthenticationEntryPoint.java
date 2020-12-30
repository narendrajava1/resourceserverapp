package com.auth.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public final class CustomAuthenticationEntryPoint implements 
        AuthenticationEntryPoint {
    @Override
    public void commence(final HttpServletRequest request, final 
            HttpServletResponse response, final AuthenticationException 
        authException) throws IOException {
    	
    	 response.setContentType(MediaType.APPLICATION_JSON_VALUE);
         response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

         final Map<String, Object> body = new HashMap<>();
         body.put("code", HttpServletResponse.SC_UNAUTHORIZED);
         body.put("payload", "You need to login first in order to perform this action.");

         final ObjectMapper mapper = new ObjectMapper();
         mapper.writeValue(response.getOutputStream(), body);
//        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}

