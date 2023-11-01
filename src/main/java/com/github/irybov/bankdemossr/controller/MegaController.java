package com.github.irybov.bankdemossr.controller;

import java.util.Arrays;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.github.irybov.bankdemossr.security.AccountDetailsService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

@Api(description = "Special controller for runtime switch of model's layer type")
@Slf4j
@RestController
public class MegaController {
	
	private final AdminController admin;
	private final AuthController auth;
	private final BankController bank;
	
	@Autowired
	private AccountDetailsService details;

	public MegaController(AdminController admin, AuthController auth, BankController bank) {
		this.admin = admin;
		this.auth = auth;
		this.bank = bank;
	}
	
	private Authentication authentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}
	
	@ApiOperation("Switchs model's layer type wired to defined controllers")
	@PreAuthorize("hasRole('ADMIN')")
	@CrossOrigin(origins="http://"+"${server.address}"+":"+"${server.port}", 
		methods = {RequestMethod.OPTIONS, RequestMethod.POST}, allowCredentials="true")
	@PutMapping("/control")
	public String changeServiceImpl(@RequestParam String impl, HttpServletResponse response) {
		
		if(impl.equals("JPA") || impl.equals("DAO")) {
		
			String bean = details.setServiceImpl(impl);
//			auth.setServiceImpl(impl);
			log.info("Admin {} has switched services impementation to {}",
					authentication().getName(), impl);
			return "Services impementation has been switched to " + bean;
		}
		else {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			return "Wrong implementation type specified, retry";
		}
	}
	
}
