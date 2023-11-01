package com.github.irybov.bankdemossr.controller;

import javax.persistence.PersistenceException;
import javax.servlet.http.HttpServletResponse;

//import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
//import org.springframework.validation.annotation.Validated;
import org.springframework.validation.Validator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.github.irybov.bankdemossr.controller.dto.AccountRequest;
import com.github.irybov.bankdemossr.controller.dto.AccountResponse;
import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.service.AccountServiceDAO;
import com.github.irybov.bankdemossr.service.AccountServiceJPA;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

@Api(description = "Controller for users authorization and registration")
@Slf4j
//@Validated
@Controller
public class AuthController extends BaseController {
	
	@Autowired
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
	
	@Qualifier("beforeCreateAccountValidator")
	private final Validator accountValidator;
	public AuthController(Validator accountValidator) {
		this.accountValidator = accountValidator;
	}

	@ApiOperation("Returns apllication's start html-page")
	@GetMapping("/home")
	public String getStartPage() {
		return "auth/home";
	}
	
	@ApiOperation("Returns registration html-page")
	@GetMapping("/register")
	public String createAccount(Model model) {
		model.addAttribute("account", new AccountRequest());
		return "auth/register";
	}
	
	@ApiOperation("Returns login form html-page")
	@GetMapping("/login")
	public String getLoginForm() {
		return "auth/login";
	}
	
	@ApiOperation("Returns welcome html-page")
	@GetMapping("/success")
	public String getRegistrationForm(Model model, RedirectAttributes redirectAttributes) {
		
		AccountResponse account;
		try {
			account = accountService.getAccountDTO(authentication().getName());
			model.addAttribute("account", account);
			log.info("User {} has enter the system", account.getPhone());
			return "auth/success";
		}
		catch (PersistenceException exc) {
			log.error(exc.getMessage(), exc);
			redirectAttributes.addFlashAttribute("message", exc.getMessage());
			return "redirect:/home";
		}
	}
	
	@ApiOperation("Confirms registration web-form")
	@PostMapping("/confirm")
	public String confirmRegistration(@ModelAttribute("account") AccountRequest accountRequest,
			BindingResult result, Model model, HttpServletResponse response) {
		
		accountValidator.validate(accountRequest, result);
		if(result.hasErrors()) {
			log.warn("{}", result.getFieldErrors().toString());
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			return "auth/register";
		}
		try {
			accountService.saveAccount(accountRequest);
			response.setStatus(HttpServletResponse.SC_CREATED);
			model.addAttribute("success", "Your account has been created");
			return "auth/login";
		}
		catch (Exception exc) {
			log.error(exc.getMessage(), exc);
			response.setStatus(HttpServletResponse.SC_CONFLICT);
			model.addAttribute("message", exc.getMessage());
			return "auth/register";
		}
	}

	@Override
	void setServiceImpl(String impl) {
		
		if(impl.equals("JPA")) accountService = context.getBean(AccountServiceJPA.class);
		else if(impl.equals("DAO")) accountService = context.getBean(AccountServiceDAO.class);
//		return accountService.getClass().getSimpleName();
	}
	
}
