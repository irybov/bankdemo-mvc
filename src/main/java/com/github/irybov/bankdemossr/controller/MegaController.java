package com.github.irybov.bankdemossr.controller;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.DefaultSingletonBeanRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.service.BillService;
import com.github.irybov.bankdemossr.service.OperationService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

@Api(description = "Special controller for runtime switch of model's layer type")
@Slf4j
@RestController
public class MegaController {

    @Autowired
    ApplicationContext context;
	
	private Authentication authentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}
	
	@ApiOperation("Switchs model's layer type wired to defined controllers")
	@PreAuthorize("hasRole('ADMIN')")
	@CrossOrigin(origins="http://"+"${server.address}"+":"+"${server.port}", 
		methods = {RequestMethod.OPTIONS, RequestMethod.POST}, allowCredentials="true")
	@PutMapping("/control")
	public String changeServiceImpl(@RequestParam String impl, HttpServletResponse response) {

	    DefaultSingletonBeanRegistry registry = 
	    		(DefaultSingletonBeanRegistry) context.getAutowireCapableBeanFactory();
	    if(impl.equals("JPA") || impl.equals("DAO")) {
		    registry.destroySingleton("accountServiceAlias");
		    AccountService as = (AccountService) context.getBean("accountService" + impl);
	    	registry.registerSingleton("accountServiceAlias", as);
		    registry.destroySingleton("billServiceAlias");
	    	BillService bs = (BillService) context.getBean("billService" + impl);
	    	registry.registerSingleton("billServiceAlias", bs);
		    registry.destroySingleton("operationServiceAlias");
	    	OperationService os = (OperationService) context.getBean("operationService" + impl);
	    	registry.registerSingleton("operationServiceAlias", os);
			log.info("Admin {} has switched services impementation to {}",
					authentication().getName(), impl);
	    	return "Services impementation has been switched to " + impl;
	    }
	    else {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			log.warn("Admin {} tried to switch services impementation to {}",
					authentication().getName(), impl);
			return String.format("Wrong implementation type %s specified, retry", impl);
	    }
	}
	
}
