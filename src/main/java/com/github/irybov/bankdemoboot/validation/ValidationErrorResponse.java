package com.github.irybov.bankdemoboot.validation;

import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class ValidationErrorResponse {

	private List<Violation> violations = new ArrayList<>();
}
