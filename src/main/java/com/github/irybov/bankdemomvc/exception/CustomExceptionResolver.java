package com.github.irybov.bankdemomvc.exception;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerExceptionResolver;

import lombok.extern.slf4j.Slf4j;

@Slf4j
//@Component
public class CustomExceptionResolver extends AbstractHandlerExceptionResolver {
	
	@Override
	protected ModelAndView doResolveException(HttpServletRequest request, HttpServletResponse response, 
			Object handler, Exception exc) {
		
		if(exc instanceof PaymentException) {
			return handlePaymentException(request, response, (PaymentException) exc);
		}
		return null;
	}

	private ModelAndView handlePaymentException(HttpServletRequest request, HttpServletResponse response, 
			PaymentException exc) {
		
		Map pathVariables = (Map) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
		String id = (String) pathVariables.get("id");
		log.warn(exc.getMessage(), exc);
		
		ModelAndView mav;
		
		if(request.getParameter("action").equals("transfer")) {
			mav = new ModelAndView("bill/transfer");
		}
		else if(request.getParameter("action").equals("external")) {
			mav = new ModelAndView("bill/external");
		}
		else {
			mav = new ModelAndView("bill/payment");
		}
		mav.addObject("id", Integer.parseInt(id));
		mav.addObject("action", request.getParameter("action"));
		mav.addObject("balance", request.getParameter("balance"));
		mav.addObject("message", exc.getMessage());
		try {
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
		catch (IOException ex) {
			ex.printStackTrace();
		}
		return mav;		
	}
	
}
