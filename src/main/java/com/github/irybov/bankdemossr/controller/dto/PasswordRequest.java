package com.github.irybov.bankdemossr.controller.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.ApiModel;
import lombok.Getter;
import lombok.Setter;

@ApiModel
@Getter
@Setter
public class PasswordRequest {

	@JsonProperty("oldPassword")
	@NotBlank
	@Size(min=10, max=60, message = "Old password should be 10-60 symbols length")
	private String oldPassword;
	
	@JsonProperty("newPassword")
	@NotBlank
	@Size(min=10, max=60, message = "New password should be 10-60 symbols length")
	private String newPassword;
	
}
