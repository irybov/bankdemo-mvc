package com.github.irybov.bankdemomvc.controller;

import java.util.Map;

import javax.mail.MessagingException;
import javax.persistence.PersistenceException;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.ConcurrentReferenceHashMap;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.validation.Validator;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.irybov.bankdemomvc.controller.dto.AccountRequest;
import com.github.irybov.bankdemomvc.controller.dto.AccountResponse;
import com.github.irybov.bankdemomvc.security.AccountDetails;
import com.github.irybov.bankdemomvc.security.EmailService;
import com.github.irybov.bankdemomvc.service.AccountService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

@Api(description = "Controller for users authorization and registration")
@Slf4j
@Validated
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
	
	@Autowired
	private EmailService emailService;
	private Map<String, AccountRequest> accounts = new ConcurrentReferenceHashMap<>();
	@Autowired
	private Cache<String, String> cache;
/*
	@ApiOperation("Returns apllication's start html-page")
	@GetMapping("/home")
	public String getStartPage() {
		return "auth/home";
	}
*/
	@ApiOperation("Sends OTP to email")
	@PreAuthorize("hasRole('TEMP')")
	@GetMapping("/code")
	@ResponseBody
	public void getCode(@AuthenticationPrincipal AccountDetails details) {
		String email = details.getAccount().getEmail();
		String code = emailService.sendVerificationCode(email);
		cache.put(email, code);
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
		
		Authentication authentication = authentication();
		if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {		
			return "auth/login";
		}
		return "forward:/accounts/show/" + authentication.getName();
	}
	
	@ApiOperation("Returns welcome html-page")
	@GetMapping("/success")
	public String getWelcome(Model model, RedirectAttributes redirectAttributes) {
		
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
		
		String key = null;
		try {
			key = emailService.sendActivationLink(accountRequest.getEmail());
		}
		catch (MessagingException exc) {
			log.error(exc.getMessage(), exc);
			response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			model.addAttribute("message", exc.getMessage());
			return "auth/register";
		}
		accounts.putIfAbsent(key, accountRequest);
		return "auth/info";
/*		
		try {
			accountService.saveAccount(accountRequest);
			response.setStatus(HttpServletResponse.SC_CREATED);
			model.addAttribute("success", "Your account has been created");
			return "auth/login";
		}
		catch (RuntimeException exc) {
			log.error(exc.getMessage(), exc);
			response.setStatus(HttpServletResponse.SC_CONFLICT);
			model.addAttribute("message", exc.getMessage());
			return "auth/register";
		}*/
	}

	@ApiOperation("Acivates account by email link")
	@GetMapping("/activate/{tail}")
//	@Validated
	@CrossOrigin(originPatterns = "*", methods = RequestMethod.GET, allowCredentials="true")
	public String activateAccount(@PathVariable 
			@NotBlank(message = "Path variable must not be blank") 
			@Size(min=8, max=8, message = "Path variable should be 8 chars length") String tail, 
			Model model, HttpServletResponse response) {
		
		if(accounts.containsKey(tail)) {
			AccountRequest accountRequest = accounts.get(tail);
		
			try {
				accountService.saveAccount(accountRequest);
				response.setStatus(HttpServletResponse.SC_CREATED);
				model.addAttribute("success", "Your account has been created");
				accounts.remove(tail);
				return "auth/login";
			}
			catch (RuntimeException exc) {
				log.error(exc.getMessage(), exc);
				response.setStatus(HttpServletResponse.SC_CONFLICT);
				model.addAttribute("message", exc.getMessage());
				accounts.remove(tail);
				return "auth/home";
			}
		}
		
		response.setStatus(HttpServletResponse.SC_GONE);
		model.addAttribute("message", "Link has been expired, try to register again");
		return "auth/home";
	}
	
}
