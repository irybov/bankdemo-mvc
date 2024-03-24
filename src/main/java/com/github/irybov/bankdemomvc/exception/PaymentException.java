package com.github.irybov.bankdemomvc.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
public class PaymentException extends RuntimeException {

	public PaymentException(String message) {
		super(message);
	}
}
