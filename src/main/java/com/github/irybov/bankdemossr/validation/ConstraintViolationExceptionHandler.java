package com.github.irybov.bankdemossr.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.ModelAndView;

import com.github.irybov.bankdemossr.controller.BankController;
import com.github.irybov.bankdemossr.exception.PaymentException;

//@ControllerAdvice(basePackages = "com.github.irybov.bankdemoboot.controller")
@ControllerAdvice(basePackageClasses = BankController.class)
public class ConstraintViolationExceptionHandler {

//	@ExceptionHandler(ConstraintViolationException.class)
//	@ResponseBody
//	ValidationErrorResponse onConstraintValidationException(ConstraintViolationException exc) {
	ModelAndView handleConstraintValidation(ConstraintViolationException exc) {		
				
	    ValidationErrorResponse error = new ValidationErrorResponse();	    
/*	    for(ConstraintViolation<?> violation : exc.getConstraintViolations()) {
	    	error.getViolations().add(new Violation(violation.getMessage()));
	    }
	    return error;*/
		ModelAndView mav = new ModelAndView("error");
		List<Violation> violations = error.getViolations();
		mav.addObject("violations", violations);
		return mav;
	}
	
	@ExceptionHandler(MethodArgumentNotValidException.class)
	@ResponseBody
	ResponseEntity<List<String>> handleMethodArgumentNotValid(MethodArgumentNotValidException exc) {		
				
	    List<String> errors = new ArrayList<String>();
	    for(FieldError error : exc.getBindingResult().getFieldErrors()) {
	        errors.add(error.getDefaultMessage());
	    }
		return new ResponseEntity<List<String>>(errors, HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(PaymentException.class)
	ModelAndView handlePaymentException(HttpServletRequest request, HttpServletResponse response, 
			PaymentException exc) {
		
		Map pathVariables = (Map) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
		String id = (String) pathVariables.get("id");
		
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
		response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		return mav;		
	}
	
}
