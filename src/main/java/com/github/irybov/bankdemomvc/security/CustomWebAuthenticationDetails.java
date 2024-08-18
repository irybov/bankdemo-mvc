package com.github.irybov.bankdemomvc.security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class CustomWebAuthenticationDetails extends WebAuthenticationDetails {
	
	private final String code;
	public CustomWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
		this.code = request.getParameter("code");
	}
    public String getCode() {
        return code;
    }
    
}
