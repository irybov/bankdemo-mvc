package com.github.irybov.bankdemomvc.controller;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import static org.hamcrest.CoreMatchers.any;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.refEq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import javax.mail.MessagingException;
import javax.persistence.PersistenceException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;

//import java.io.File;
//import java.nio.file.Files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.validation.beanvalidation.MethodValidationPostProcessor;

import com.github.irybov.bankdemomvc.config.SecurityBeans;
import com.github.irybov.bankdemomvc.config.SecurityConfig;
import com.github.irybov.bankdemomvc.controller.AuthController;
import com.github.irybov.bankdemomvc.controller.dto.AccountRequest;
import com.github.irybov.bankdemomvc.controller.dto.AccountResponse;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.exception.RegistrationException;
import com.github.irybov.bankdemomvc.security.AccountDetails;
import com.github.irybov.bankdemomvc.security.AccountDetailsService;
import com.github.irybov.bankdemomvc.security.EmailService;
import com.github.irybov.bankdemomvc.security.Role;
import com.github.irybov.bankdemomvc.service.AccountService;

import net.bytebuddy.utility.RandomString;

@WebMvcTest(AuthController.class)
@Import(SecurityBeans.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthControllerTest {

	@MockBean
	@Qualifier("beforeCreateAccountValidator")
	private Validator accountValidator;
	@MockBean
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
	@MockBean
	private UserDetailsService accountDetailsService;
	@Autowired
	private MockMvc mockMVC;
	
	@Autowired
	ApplicationContext context;
	
	@MockBean
	private EmailService emailService;
	private Map<String, AccountRequest> accounts;
	
	private Authentication authentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}
	
	private String mailbox;
	@Value("${external.payment-service}")
	private String externalURL;
	
	@BeforeAll
	void set_up() {
		mailbox = "@greenmail.io";
		accounts = mock(Map.class);
		ReflectionTestUtils.setField(context.getBean(AuthController.class), "accounts", accounts);
		ReflectionTestUtils.setField(context.getBean(AuthController.class), "accountService", accountService);
	}
	
	private AccountRequest buildCorrectAccountRequest() {
		AccountRequest accountRequest = new AccountRequest();
		accountRequest.setBirthday(LocalDate.of(2001, 01, 01));
		accountRequest.setName("Admin");
		accountRequest.setPassword("superadmin");
		accountRequest.setPhone("0000000000");
		accountRequest.setSurname("Adminov");
		accountRequest.setEmail(accountRequest.getSurname().toLowerCase() + mailbox);
		return accountRequest;
	}
/*	
	@TestConfiguration
	static class ValidationConfig {
		
	     @Bean
	     @Primary
	     public MethodValidationPostProcessor methodValidationPostProcessor() {      
	          return new MethodValidationPostProcessor();
	     }
	     @Bean
	     @Primary
	     public LocalValidatorFactoryBean localValidatorFactoryBean() {
	         return new LocalValidatorFactoryBean();
	     }
	}
*/	
	@Test
	void can_get_start_html() throws Exception {
		
//		File home = new ClassPathResource("templates/auth/home.html").getFile();
//		String html = new String(Files.readAllBytes(home.toPath()));
		
        mockMVC.perform(get("/home"))
	        .andExpect(status().isOk())
	//        .andExpect(content().string(html))
	        .andExpect(content().string(containsString("Welcome!")))
	        .andExpect(view().name("auth/home"));
	}
	
	@Test
	void can_get_registration_form() throws Exception {
		
        mockMVC.perform(get("/register"))
	        .andExpect(status().isOk())
	        .andExpect(content().string(containsString("Registration")))
	        .andExpect(model().size(1))
	        .andExpect(model().attributeExists("account"))
	        .andExpect(view().name("auth/register"));
	}

	@Test
	void can_get_login_form() throws Exception {
		
//		File login = new ClassPathResource("templates/auth/login.html").getFile();
//		String html = new String(Files.readAllBytes(login.toPath()));
		
        mockMVC.perform(get("/login"))
	        .andExpect(status().isOk())
	//        .andExpect(content().string(html))
	        .andExpect(content().string(containsString("Log In")))
	        .andExpect(view().name("auth/login"));
	}
	
	@WithMockUser(username = "0000000000", roles = {"ADMIN", "CLIENT"})
	@Test
	void can_get_menu_html() throws Exception {

		ModelMapper modelMapper = new ModelMapper();
		AccountResponse accountResponse = modelMapper.map(new Account
				("Admin", "Adminov", "0000000000", "adminov@greenmail.io", LocalDate.of(2001, 01, 01), "superadmin", true), 
				AccountResponse.class);
		
		when(accountService.getAccountDTO(anyString())).thenReturn(accountResponse);
		
		String roles = authentication().getAuthorities().toString();
		assertThat(authentication().getName()).isEqualTo("0000000000");
		assertThat(roles).isEqualTo("[ROLE_ADMIN, ROLE_CLIENT]");
		
		mockMVC.perform(get("/success"))
			.andExpect(status().isOk())
			.andExpect(authenticated())
			.andExpect(content().string(containsString("Welcome!")))
			.andExpect(content().string(containsString(accountResponse.getName()+" "
					+accountResponse.getSurname())))
			.andExpect(content().string(containsString(roles)))
	        .andExpect(model().size(1))
	        .andExpect(model().attribute("account", accountResponse))
	        .andExpect(view().name("auth/success"));
	    
	    verify(accountService).getAccountDTO(anyString());
	}
	
	@WithMockUser(username = "0000000000", roles = {"ADMIN", "CLIENT"})
	@Test
	void forward_to_private() throws Exception {
		
		String phone = authentication().getName();
		
		assertThat(phone).isEqualTo("0000000000");
		
        mockMVC.perform(get("/login"))
	        .andExpect(status().is2xxSuccessful())
	        .andExpect(forwardedUrl("/accounts/show/" + phone));
	}
	
	@Test
	void correct_user_creds() throws Exception {

		final String hashedPW = BCrypt.hashpw("superadmin", BCrypt.gensalt(4));
		
		when(accountDetailsService.loadUserByUsername(anyString()))
			.thenReturn(new AccountDetails(new Account
			("Admin", "Adminov", "0000000000", "adminov@greenmail.io", LocalDate.of(2001, 01, 01), hashedPW, true)));

		mockMVC.perform(formLogin("/auth").user("phone", "0000000000").password("superadmin"))
			.andExpect(authenticated())
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/success"));
		
	    verify(accountDetailsService).loadUserByUsername(anyString());
	}
	
	@Test
	void wrong_user_password() throws Exception {
		
		Account account = new Account("Admin", "Adminov", "0000000000", "adminov@greenmail.io", LocalDate.of(2001, 01, 01),
				 BCrypt.hashpw("superadmin", BCrypt.gensalt(4)), true);
		
		when(accountDetailsService.loadUserByUsername(anyString()))
//			.thenThrow(new UsernameNotFoundException("User 9999999999 not found"));
			.thenReturn(new AccountDetails(account));
		
		for(int i = 1; i < 4; i++) {
		mockMVC.perform(formLogin("/auth").user("phone", "0000000000").password("localadmin"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login?error=true"))
			.andExpect(result -> assertThat
//				(result.getResolvedException() instanceof UsernameNotFoundException))
				(result.getResolvedException() instanceof BadCredentialsException))
//			.andExpect(result -> assertEquals
//				("User 9999999999 not found", result.getResolvedException().getMessage()))
//				("Bad Credentials", result.getResolvedException().getMessage()))
			.andDo(print());
		}
		
		mockMVC.perform(formLogin("/auth").user("phone", "0000000000").password("localadmin"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login?error=true"))
			.andExpect(result -> assertThat
				(result.getResolvedException() instanceof DisabledException))
//			.andExpect(result -> assertEquals
//				("User is disabled", result.getResolvedException().getMessage()));
			.andDo(print());
		
	    verify(accountDetailsService, times(4)).loadUserByUsername(anyString());
	}
	
	@WithMockUser(username = "9999999999")
	@Test
	void entity_not_found() throws Exception {
		
		String phone = authentication().getName();
		when(accountService.getAccountDTO(anyString())).thenThrow(new PersistenceException
							("Account with phone " + phone + " not found"));
		
		assertThat(phone).isEqualTo("9999999999");
		
		mockMVC.perform(get("/success"))
			.andExpect(authenticated())
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/home"));
	    
	    verify(accountService).getAccountDTO(anyString());
	}
	
	@Test
	void unauthorized_denied() throws Exception {
		mockMVC.perform(get("/success"))
			.andExpect(unauthenticated())
			.andExpect(status().is3xxRedirection());
		mockMVC.perform(post("/confirm")).andExpect(status().isForbidden());
	}
	
	@WithAnonymousUser
	@Test
	void anonimuos_allowed() throws Exception {
		mockMVC.perform(get("/home")).andExpect(status().isOk());
		mockMVC.perform(get("/register")).andExpect(status().isOk());
	}
	
	@WithMockUser(username = "0000000000", roles = "ADMIN")
	@Test
	void authorized_refused() throws Exception {
		mockMVC.perform(get("/home")).andExpect(status().isForbidden());
		mockMVC.perform(get("/register")).andExpect(status().isForbidden());
	}
	
	@WithMockUser(username = "0000000000", roles = "ADMIN")
	@Test
	void logout() throws Exception {
		mockMVC.perform(post("/logout").with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/home?logout=true"));
	}
	
	@Test
	void accepted_registration() throws Exception {
		
		AccountRequest accountRequest = buildCorrectAccountRequest();
		String tail = RandomString.make();

		when(emailService.sendActivationLink(accountRequest.getEmail())).thenReturn(tail);
		
		mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest))
//			.andExpect(status().isCreated())
//	        .andExpect(model().size(2))
//	        .andExpect(model().attributeExists("account"))
//	        .andExpect(model().attribute("success", "Your account has been created"))
//			.andExpect(view().name("auth/login"));
			.andExpect(status().isOk())
			.andExpect(view().name("auth/info"));
		
		verify(emailService).sendActivationLink(accountRequest.getEmail());
		assertEquals(tail, emailService.sendActivationLink(accountRequest.getEmail()));
	}
	
	@Test
	void rejected_registration() throws Exception {
		
		AccountRequest accountRequest = new AccountRequest();
		accountRequest.setBirthday(null);
		accountRequest.setName("i");
		accountRequest.setPassword("superb");
		accountRequest.setPhone("xxx");
		accountRequest.setSurname("a");

		mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest))
			.andExpect(status().isBadRequest())
	        .andExpect(model().size(1))
	        .andExpect(model().attributeExists("account"))
	        .andExpect(model().hasErrors())
			.andExpect(view().name("auth/register"));
		
		accountRequest.setBirthday(LocalDate.now().plusYears(10L));		
		mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest))
			.andExpect(status().isBadRequest())
	        .andExpect(model().size(1))
	        .andExpect(model().attributeExists("account"))
	        .andExpect(model().hasErrors())
			.andExpect(view().name("auth/register"));
		
		accountRequest.setBirthday(LocalDate.now().minusYears(10L));		
		mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest))
			.andExpect(status().isBadRequest())
	        .andExpect(model().size(1))
	        .andExpect(model().attributeExists("account"))
	        .andExpect(model().hasErrors())
			.andExpect(view().name("auth/register"));
		
		verify(emailService, never()).sendActivationLink(accountRequest.getEmail());
	}
	
	@Test
	void interrupted_registration() throws Exception {
		
		AccountRequest accountRequest = buildCorrectAccountRequest();
		
		doThrow(new MessagingException("Shit happens")).when(emailService).sendActivationLink(accountRequest.getEmail());
		
		mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest))
			.andExpect(status().isInternalServerError())
	        .andExpect(model().size(2))
	        .andExpect(model().attributeExists("account"))
        	.andExpect(model().attribute("message", "Shit happens"))
			.andExpect(view().name("auth/register"));
		
		verify(emailService).sendActivationLink(accountRequest.getEmail());
	}
	
	@Test
	void successful_activation() throws Exception {
		
		AccountRequest accountRequest = buildCorrectAccountRequest();
		String tail = RandomString.make();
		
		doNothing().when(accountService).saveAccount(refEq(accountRequest));
		when(accounts.containsKey(tail)).thenReturn(true);
		when(accounts.get(tail)).thenReturn(accountRequest);
		when(accounts.remove(tail)).thenReturn(accountRequest);
		
		mockMVC.perform(get("/activate/{tail}", tail).with(csrf()).header("Origin", externalURL))
			.andExpect(status().isCreated())
	        .andExpect(model().size(1))
        	.andExpect(model().attribute("success", "Your account has been created"))
			.andExpect(view().name("auth/login"));
		
	    verify(accountService).saveAccount(refEq(accountRequest));
		verify(accounts).containsKey(tail);
	    verify(accounts).get(tail);
	    verify(accounts).remove(tail);
	}

	@Test
	void failed_activation() throws Exception {
		
		AccountRequest accountRequest = buildCorrectAccountRequest();
		String tail = RandomString.make();
		
		doThrow(new RuntimeException("This number is already in use"))
			.when(accountService).saveAccount(refEq(accountRequest));
		when(accounts.containsKey(tail)).thenReturn(true);
		when(accounts.get(tail)).thenReturn(accountRequest);
		
		mockMVC.perform(get("/activate/{tail}", tail).with(csrf()).header("Origin", externalURL))
			.andExpect(status().isConflict())
	        .andExpect(model().size(1))
        	.andExpect(model().attribute("message", "This number is already in use"))
			.andExpect(view().name("auth/home"));
		
	    verify(accountService).saveAccount(refEq(accountRequest));
	    verify(accounts).get(tail);
	    
	    
	    when(accounts.containsKey(tail)).thenReturn(false);
	    
		mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
			.andExpect(status().isGone())
	        .andExpect(model().size(1))
	    	.andExpect(model().attribute("message", "Link has been expired, try to register again"))
			.andExpect(view().name("auth/home"));
		
		verify(accounts, times(2)).containsKey(tail);
	}
	
	@Test
	void violated_activation() throws Exception {
		
		String tail = "tail";		
		mockMVC.perform(get("/activate/{tail}", tail).with(csrf()).header("Origin", externalURL))
			.andExpect(status().isBadRequest())
	        .andExpect(model().size(1))
	    	.andExpect(model().attribute("violations", any(List.class)))
	    	.andExpect(content().string(containsString("Path variable should be 8 chars length")))
			.andExpect(view().name("error"));
		
		tail = " ";
		mockMVC.perform(get("/activate/{tail}", tail).with(csrf()).header("Origin", externalURL))
			.andExpect(status().isBadRequest())
	        .andExpect(model().size(1))
	    	.andExpect(model().attribute("violations", any(List.class)))
	    	.andExpect(content().string(containsString("Path variable must not be blank")))
			.andExpect(view().name("error"));
		
		tail = "";
		mockMVC.perform(get("/activate/{tail}", tail).with(csrf()).header("Origin", externalURL))
			.andExpect(status().isNotFound());
		tail = null;
		mockMVC.perform(get("/activate/{tail}", tail).with(csrf()).header("Origin", externalURL))
			.andExpect(status().isNotFound());
	}
	
    @AfterAll
    void tear_down() {
    	accounts = null;
    	mailbox = null;
    }
}
