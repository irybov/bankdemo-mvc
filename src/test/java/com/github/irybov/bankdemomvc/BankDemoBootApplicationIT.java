package com.github.irybov.bankdemomvc;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.hamcrest.CoreMatchers.any;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.MimeMessage;

import org.awaitility.Awaitility;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ConcurrentReferenceHashMap;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.github.irybov.bankdemomvc.controller.AuthController;
import com.github.irybov.bankdemomvc.controller.dto.AccountRequest;
import com.github.irybov.bankdemomvc.controller.dto.AccountResponse;
import com.github.irybov.bankdemomvc.controller.dto.OperationRequest;
import com.github.irybov.bankdemomvc.controller.dto.PasswordRequest;
import com.github.irybov.bankdemomvc.dao.AccountDAO;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.jpa.AccountJPA;
import com.github.irybov.bankdemomvc.security.AccountDetailsService;
import com.github.irybov.bankdemomvc.security.LoginListener;
import com.github.irybov.bankdemomvc.security.UnlockService;
import com.github.irybov.bankdemomvc.service.AccountService;
import com.github.irybov.bankdemomvc.service.AccountServiceDAO;
import com.github.irybov.bankdemomvc.service.AccountServiceJPA;
import com.github.irybov.bankdemomvc.service.BillServiceDAO;
import com.github.irybov.bankdemomvc.service.BillServiceJPA;
import com.github.irybov.bankdemomvc.service.OperationServiceDAO;
import com.github.irybov.bankdemomvc.service.OperationServiceJPA;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.icegreen.greenmail.configuration.GreenMailConfiguration;
import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.GreenMailUtil;
import com.icegreen.greenmail.util.ServerSetupTest;

@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT)
//@Sql("/test-data-h2.sql")
@AutoConfigureMockMvc
@Transactional
public class BankDemoBootApplicationIT {

	@Autowired
	private MockMvc mockMVC;
	
	private static WireMockServer wireMockServer;
	@Value("${external.payment-service}")
	private static String externalURL;
	
	@BeforeAll
	static void prepare() {
		wireMockServer = new WireMockServer(new WireMockConfiguration().port(4567));
	    wireMockServer.start();
	    WireMock.configureFor(externalURL, 4567);
	}
	
	private Authentication authentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}

	@Test
	void contextLoads(ApplicationContext context) {
		assertThat(context).isNotNull();
	}
	
    @Nested
    class ActuatorAccessIT{
    	
		@Autowired
		@Qualifier("accountServiceAlias")
		private AccountService accountService;
/*		@Autowired
		private AccountJPA jpa;
		@Autowired
		private AccountDAO dao;*/
	
//		@WithMockUser(username = "remote", roles = "REMOTE")
		@Test
		void actuator_allowed() throws Exception {
			
	        mockMVC.perform(get("/actuator/").with(httpBasic("remote", "remote")))
	    		.andExpect(status().isOk());
		}
		
		@Test
		void actuator_denied() throws Exception {
			
	        mockMVC.perform(get("/actuator/").with(httpBasic("0000000000", "superadmin")))
	    		.andExpect(status().isUnauthorized());
		}
		
//		@WithMockUser(username = "3333333333", roles = {"ADMIN", "CLIENT"})
		@Test
		void actuator_forbidden() throws Exception {
/*			
			Account account = null;
			if(accountService instanceof AccountServiceJPA) {
				account = jpa.findByPhone("3333333333").get();
				account.setPassword(BCrypt.hashpw(account.getPassword(), BCrypt.gensalt(4)));
				jpa.saveAndFlush(account);
			}
			else if(accountService instanceof AccountServiceDAO) {
				account = dao.getAccount("3333333333");
				account.setPassword(BCrypt.hashpw(account.getPassword(), BCrypt.gensalt(4)));
				dao.updateAccount(account);
			}
			*/
	        mockMVC.perform(get("/actuator/").with(httpBasic("admin", "admin")))
	    		.andExpect(status().isForbidden());
		}
		
	}	
	
	@WithMockUser(username = "3333333333", roles = {"ADMIN", "CLIENT"})
    @Nested
    class SwaggerAccessIT{
    	
		@Test
		void swagger_allowed() throws Exception {
			
	        mockMVC.perform(get("/swagger-ui/"))
	    		.andExpect(status().isOk());
		}
		
		@WithMockUser(username = "1111111111", roles = "CLIENT")
		@Test
		void swagger_denied() throws Exception {
			
	        mockMVC.perform(get("/swagger-ui/"))
				.andExpect(status().isForbidden());
		}

	    @Disabled
	    @Test
	    void can_get_swagger_html() throws Exception {

	        mockMVC.perform(get("/swagger-ui.html"))
	        	.andExpect(status().isOk());
	    }
		
	    @Test
	    void can_get_api_docs() throws Exception {

	        mockMVC.perform(get("/v2/api-docs"))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON));		
		}
	    
	    @WithMockUser(username = "1111111111", roles = "CLIENT")
	    @Test
	    void denied_api_docs() throws Exception {

	        mockMVC.perform(get("/v2/api-docs"))
				.andExpect(status().isForbidden());		
		}

	    @Disabled
	    @Test
	    void can_get_swagger_config() throws Exception {

	        mockMVC.perform(get("/v2/api-docs/swagger-config"))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON));		
		}
		
    }	

	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@Nested
	class AuthControllerIT{
		
		@Autowired
		@Qualifier("accountServiceAlias")
		private AccountService accountService;
		@Autowired
		private AccountJPA jpa;
		@Autowired
		private AccountDAO dao;
		
	    @Autowired
	    ApplicationContext context;
	    private Map<String, AccountRequest> accounts = new ConcurrentReferenceHashMap<>();
	    
		@Value("${server.address}")
		private String uri;
		@Value("${server.port}")
		private int port;
		@Value("${server.servlet.context-path}")
		private String path;
	    
		@RegisterExtension
		GreenMailExtension greenMail = new GreenMailExtension(ServerSetupTest.SMTP)
		        .withConfiguration(GreenMailConfiguration.aConfig().withUser("irybov", "bankdemo"))
		        .withPerMethodLifecycle(false);
		
		private static final String PHONE = "0000000000";				
		private void hashPassword() {
			
			Account account = null;
			if(accountService instanceof AccountServiceJPA) {
				account = jpa.findByPhone(PHONE).get();
				account.setPassword(BCrypt.hashpw(account.getPassword(), BCrypt.gensalt(4)));
				jpa.saveAndFlush(account);
			}
			else if(accountService instanceof AccountServiceDAO) {
				account = dao.getAccount(PHONE);
				account.setPassword(BCrypt.hashpw(account.getPassword(), BCrypt.gensalt(4)));
				dao.updateAccount(account);
			}
		}
		
		private String mailbox = "@greenmail.io";
		private AccountRequest buildCorrectAccountRequest() {
			AccountRequest accountRequest = new AccountRequest();
			accountRequest.setBirthday(LocalDate.of(1989, 01, 30));
			accountRequest.setName("Kylie");
			accountRequest.setPassword("blackmamba");
			accountRequest.setPhone("4444444444");
			accountRequest.setSurname("Bunbury");
			accountRequest.setEmail(accountRequest.getSurname().toLowerCase() + mailbox);
			return accountRequest;
		}
	
		@Test
		void can_get_start_html() throws Exception {
			
	        mockMVC.perform(get("/home"))
	        	.andExpect(status().isOk())
	        	.andExpect(content().string(containsString("Welcome!")))
	        	.andExpect(view().name("auth/home"));
		}
		
		@Test
		void can_get_registration_form() throws Exception {

	        mockMVC.perform(get("/register"))
		        .andExpect(status().isOk())
		        .andExpect(content().string(containsString("Registration")))
		        .andExpect(model().size(1))
		        .andExpect(model().attribute("account", any(AccountRequest.class)))
		        .andExpect(view().name("auth/register"));
		}
	
		@Test
		void can_get_login_form() throws Exception {
			
	        mockMVC.perform(get("/login"))
		        .andExpect(status().isOk())
		        .andExpect(content().string(containsString("Log In")))
		        .andExpect(view().name("auth/login"));
		}
		
		@WithMockUser(username = PHONE, roles = "ADMIN")
		@Test
		void can_get_menu_html() throws Exception {
			
			String roles = authentication().getAuthorities().toString();
			assertThat(authentication().getName()).isEqualTo(PHONE);
			assertThat(roles).isEqualTo("[ROLE_ADMIN]");

			mockMVC.perform(get("/success").with(csrf()))
				.andExpect(status().isOk())
				.andExpect(authenticated())
				.andExpect(content().string(containsString("Welcome!")))
				.andExpect(content().string(containsString("Admin Adminov")))
				.andExpect(content().string(containsString("[ROLE_ADMIN]")))
		        .andExpect(model().size(1))
		        .andExpect(model().attribute("account", any(AccountResponse.class)))
		        .andExpect(view().name("auth/success"));
		}
		
		
		@WithMockUser(username = PHONE, roles = "ADMIN")
		@Test
		void forward_to_private() throws Exception {
			
	        mockMVC.perform(get("/login"))
		        .andExpect(status().is2xxSuccessful())
		        .andExpect(forwardedUrl("/accounts/show/" + PHONE));
		}
		
		@Test
		void correct_user_creds() throws Exception {
			
			hashPassword();

			mockMVC.perform(formLogin("/auth").user("phone", PHONE).password("superadmin"))
				.andExpect(authenticated())
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/success"));
		}
		
		@Test
		void wrong_user_password() throws Exception {
			
			hashPassword();
			
			for(int i = 1; i < 4; i++) {
			mockMVC.perform(formLogin("/auth").user("phone", PHONE).password("localadmin"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/login?error=true"))
				.andExpect(result -> assertThat
					(result.getResolvedException() instanceof BadCredentialsException))
//				.andExpect(result -> assertEquals
//					("Bad Credentials", result.getResolvedException().getMessage()))
				.andDo(print());
			}
			mockMVC.perform(formLogin("/auth").user("phone", PHONE).password("superladmin"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/login?error=true"))
				.andExpect(result -> assertThat
					(result.getResolvedException() instanceof DisabledException))
//				.andExpect(result -> assertEquals
//					("User is disabled", result.getResolvedException().getMessage()))
				.andDo(print());
		}
		
		@WithMockUser(username = "9999999999")
		@Test
		void entity_not_found() throws Exception {
			
			String phone = authentication().getName();			
			assertThat(phone).isEqualTo("9999999999");
			
			mockMVC.perform(get("/success"))
				.andExpect(authenticated())
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/home"));
		}
		
		@Test
		void unauthorized_denied() throws Exception {
			mockMVC.perform(post("/confirm")).andExpect(status().isForbidden());			
		}
		
		@Test
		void accepted_registration() throws Exception {
			
			AccountRequest accountRequest = buildCorrectAccountRequest();			
			mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest)
//										 .param("birthday", "1998-12-10")
//										 .param("name", "Nia")
//										 .param("password", "blackmamba")
//										 .param("phone", "4444444444")
//										 .param("surname", "Nacci")
						)
//				.andExpect(status().isCreated())
//		        .andExpect(model().size(2))
//		        .andExpect(model().attribute("account", any(AccountRequest.class)))
//		        .andExpect(model().attribute("success", "Your account has been created"))
//				.andExpect(view().name("auth/login"));
				.andExpect(status().isOk())
				.andExpect(view().name("auth/info"));
			
			Awaitility.await().untilAsserted(() -> {
				assertEquals(true, greenMail.isRunning());
				MimeMessage receivedMessage = greenMail.getReceivedMessages()[0];
				assertEquals(1, receivedMessage.getAllRecipients().length);
				assertEquals(accountRequest.getSurname().toLowerCase() + mailbox, receivedMessage.getAllRecipients()[0].toString());
				assertEquals("noreply@bankdemo.com", receivedMessage.getFrom()[0].toString());
				assertEquals("Confirm your registration", receivedMessage.getSubject());
				assertFalse(GreenMailUtil.getBody(receivedMessage).isEmpty());
				assertTrue(GreenMailUtil.getBody(receivedMessage)
						.startsWith("<a href='http://" + uri + ":" + port + path + "/activate/"));
				assertTrue(GreenMailUtil.getBody(receivedMessage)
						.endsWith("'>Activate your account</a>"));
				assertFalse(GreenMailUtil.getBody(receivedMessage).contains("Shit happens"));
			});
		}
		
		@Test
		void rejected_registration() throws Exception {
			
			mockMVC.perform(post("/confirm").with(csrf())
										 .param("birthday", LocalDate.now().minusYears(10L).toString())
										 .param("name", "N")
										 .param("password", "superb")
										 .param("phone", "XXL")
										 .param("surname", "N")
										 .param("email", "invalid")
						)
				.andExpect(status().isBadRequest())
				.andExpect(model().size(1))
				.andExpect(model().attribute("account", any(AccountRequest.class)))
				.andExpect(model().hasErrors())
				.andExpect(view().name("auth/register"));
			
			mockMVC.perform(post("/confirm").with(csrf())
										 .param("birthday", LocalDate.now().plusYears(10L).toString())
										 .param("name", "N")
										 .param("password", "superb")
										 .param("phone", "XXL")
										 .param("surname", "N")
										 .param("email", "invalid")
						)
				.andExpect(status().isBadRequest())
				.andExpect(model().size(1))
				.andExpect(model().attribute("account", any(AccountRequest.class)))
				.andExpect(model().hasErrors())
				.andExpect(view().name("auth/register"));
			
			mockMVC.perform(post("/confirm").with(csrf())
										 .param("birthday", LocalDate.now().minusYears(10L).toString())
										 .param("name", "Kylie")
										 .param("password", "blackmamba")
										 .param("phone", "4444444444")
										 .param("surname", "Bunbury")
										 .param("email", "bunbury@greenmail.io")
						)
				.andExpect(status().isBadRequest())
				.andExpect(model().size(1))
				.andExpect(model().attribute("account", any(AccountRequest.class)))
				.andExpect(content().string(containsString("Validator in action!")))
				.andExpect(view().name("auth/register"));
			
			mockMVC.perform(post("/confirm").with(csrf())
										 .param("birthday", "1989-01-30")
										 .param("name", "Kylie")
										 .param("password", "blackmamba")
										 .param("phone", "0000000000")
										 .param("surname", "Bunbury")
										 .param("email", "bunbury@greenmail.io")
						)
				.andExpect(status().isBadRequest())
				.andExpect(model().size(1))
				.andExpect(model().attribute("account", any(AccountRequest.class)))
				.andExpect(content().string(containsString("Validator in action!")))
				.andExpect(view().name("auth/register"));
		}

		@Test
		void successful_activation() throws Exception {
			
			ReflectionTestUtils.setField(context.getBean(AuthController.class), "accounts", accounts);
			
			AccountRequest accountRequest = buildCorrectAccountRequest();
			mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest))
				.andExpect(status().isOk())
				.andExpect(view().name("auth/info"));
			
			List<String> keys = new ArrayList<>(accounts.keySet());
			String tail = keys.get(0);
			
			mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
				.andExpect(status().isCreated())
		        .andExpect(model().size(1))
	        	.andExpect(model().attribute("success", "Your account has been created"))
				.andExpect(view().name("auth/login"));
		}
		
		@Test
		void failed_activation() throws Exception {
			
			ReflectionTestUtils.setField(context.getBean(AuthController.class), "accounts", accounts);
			
			AccountRequest accountRequest = buildCorrectAccountRequest();			
			mockMVC.perform(post("/confirm").with(csrf()).flashAttr("account", accountRequest))
				.andExpect(status().isOk())
				.andExpect(view().name("auth/info"));
			
			List<String> keys = new ArrayList<>(accounts.keySet());
			String tail = keys.get(0);
			accountRequest = accounts.get(tail);
			accountRequest.setPhone(PHONE);
			
			accounts.put(tail, accountRequest);
			mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
				.andExpect(status().isConflict())
		        .andExpect(model().size(1))
//	        	.andExpect(model().attribute("message", "This number is already in use"))
	        	.andExpect(model().attributeExists("message"))
				.andExpect(view().name("auth/home"));
			
			mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
				.andExpect(status().isGone())
		        .andExpect(model().size(1))
		    	.andExpect(model().attribute("message", "Link has been expired, try to register again"))
				.andExpect(view().name("auth/home"));
		}
		
		@Test
		void violated_activation() throws Exception {
			
			String tail = "tail";		
			mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
				.andExpect(status().isBadRequest())
		        .andExpect(model().size(1))
		    	.andExpect(model().attribute("violations", any(List.class)))
		    	.andExpect(content().string(containsString("Path variable should be 8 chars length")))
				.andExpect(view().name("error"));
			
			tail = " ";
			mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
				.andExpect(status().isBadRequest())
		        .andExpect(model().size(1))
		    	.andExpect(model().attribute("violations", any(List.class)))
		    	.andExpect(content().string(containsString("Path variable must not be blank")))
				.andExpect(view().name("error"));
			
			tail = "";
			mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
				.andExpect(status().isNotFound());
			tail = null;
			mockMVC.perform(get("/activate/{tail}", tail).with(csrf()))
				.andExpect(status().isNotFound());
		}
		
	}
	
	@WithMockUser(username = "0000000000", roles = "ADMIN")
	@Nested
	@Sql("/test-operations-h2.sql")
	class AdminControllerIT{
		
	    @Test
		void can_get_admin_html() throws Exception {
	    	
			mockMVC.perform(get("/accounts/search"))
				.andExpect(status().isOk())
				.andExpect(model().size(1))
		        .andExpect(model().attribute("account", any(AccountResponse.class)))
				.andExpect(content().string(containsString("Admin's area")))
		        .andExpect(view().name("account/search"));
	    }
		
		@Test
		void can_get_history_html() throws Exception {
			
			mockMVC.perform(get("/operations/list"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Operations history")))
				.andExpect(view().name("account/history"));
		}
		
		@Test
		void can_get_clients_html() throws Exception {
			
			mockMVC.perform(get("/accounts/list"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Clients list")))
		        .andExpect(view().name("account/clients"));
		}
		
		@Test
		void can_get_clients_list() throws Exception {
			
			MvcResult result = mockMVC.perform(get("/accounts/list/all"))
				.andExpect(request().asyncStarted())
				.andReturn();
					
			mockMVC.perform(asyncDispatch(result))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_OCTET_STREAM_VALUE));
		}
		
		@Disabled
		@Test
		void clients_not_found_exception() throws Exception {
			
			MvcResult result = mockMVC.perform(get("/accounts/list/all"))
				.andExpect(request().asyncStarted())
				.andReturn();
					
			mockMVC.perform(asyncDispatch(result))
				.andExpect(status().isInternalServerError());
		}
	    
		@Test
		void can_change_account_status() throws Exception {
			
			mockMVC.perform(patch("/accounts/status/{id}", "1").with(csrf()))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("false")));
		}

		@Test
		void can_change_bill_status() throws Exception {
			
			mockMVC.perform(patch("/bills/status/{id}", "1").with(csrf()))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("false")));
		}
				
		@Test
		void input_mismatch_exception() throws Exception {
			
/*			assertThatThrownBy(() -> mockMVC.perform(get("/accounts/search/{phone}", "XXL"))
					.andExpect(status().isInternalServerError()))
					.hasCause(new InputMismatchException("Phone number should be of 10 digits"));*/
			
			mockMVC.perform(get("/accounts/search/{phone}", "XXL"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.report").value("Phone number should be of 10 digits"));
		}
		
		@Test
		void account_not_found_exception() throws Exception {
			
			String wrong = "4444444444";
			mockMVC.perform(get("/accounts/search/{phone}", wrong))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.report").value("Account with phone " + wrong + " not found"));
		}
		
		@Test
		void can_get_account_info() throws Exception {
			
			String phone = authentication().getName();
			mockMVC.perform(get("/accounts/search/{phone}", phone))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.id").isNumber())
				.andExpect(jsonPath("$.createdAt").isNotEmpty())
				.andExpect(jsonPath("$.updatedAt").isNotEmpty())
				.andExpect(jsonPath("$.active").isBoolean())
				.andExpect(jsonPath("$.name").value("Admin"))
				.andExpect(jsonPath("$.surname").value("Adminov"))
				.andExpect(jsonPath("$.phone").value(phone))
				.andExpect(jsonPath("$.birthday").isNotEmpty())
				.andExpect(jsonPath("$.bills").isArray())
				.andExpect(jsonPath("$.bills.length()", is(1)));
		}

		@Test
		void can_get_operations_page() throws Exception {
			
			mockMVC.perform(get("/operations/list/{id}", "1")
//							.param("action", "")
//							.param("minval", "")
//							.param("maxval", "")
//							.param("mindate", "")
//							.param("maxdate", "")
					)
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.pageable").exists())
				.andExpect(jsonPath("$.sort").exists())
				.andExpect(jsonPath("$.content").isArray())
				.andExpect(jsonPath("$.content.length()", is(3)));
		}
		
		@Test
		void can_export_data_2_csv_file() throws Exception {
			
			MvcResult result = mockMVC.perform(get("/operations/print/{id}", "1"))
				.andExpect(request().asyncStarted())
				.andReturn();
				
			mockMVC.perform(asyncDispatch(result))
				.andExpect(status().isCreated())
				.andExpect(content().contentType(MediaType.APPLICATION_OCTET_STREAM_VALUE));
		}
		
		@Test
		void data_on_fetch_exception() throws Exception {
			
			MvcResult result = mockMVC.perform(get("/operations/print/{id}", "0"))
				.andExpect(request().asyncStarted())
				.andReturn();
					
			mockMVC.perform(asyncDispatch(result))
				.andExpect(status().isInternalServerError())
				.andExpect(content().bytes(new byte[0]));
		}
		
	}
	
	@Sql(statements = "INSERT INTO bankdemo.bills(id, is_active, balance, currency, account_id)"
				 +" "+"VALUES('2', '1', '10.00', 'USD', '1');")
	@WithMockUser(username = "1111111111", roles = "CLIENT")
	@Nested
	class BankControllerIT{
		
		@Autowired
		private ObjectMapper mapper;
		@Autowired
		private TestRestTemplate testRestTemplate;
		
		@Autowired
		@Qualifier("accountServiceAlias")
		private AccountService accountService;
		@Autowired
		private AccountJPA jpa;
		@Autowired
		private AccountDAO dao;
		
		private static final String PHONE = "1111111111";		
		private void hashPassword() {
			
			Account account = null;
			if(accountService instanceof AccountServiceJPA) {
				account = jpa.findByPhone(PHONE).get();
				account.setPassword(BCrypt.hashpw(account.getPassword(), BCrypt.gensalt(4)));
				jpa.saveAndFlush(account);
			}
			else if(accountService instanceof AccountServiceDAO) {
				account = dao.getAccount(PHONE);
				account.setPassword(BCrypt.hashpw(account.getPassword(), BCrypt.gensalt(4)));
				dao.updateAccount(account);
			}
		}
		
		@Value("${external.payment-service}")
		private String externalURL;
		
		@Test
		void can_get_client_html() throws Exception {
			
			mockMVC.perform(get("/accounts/show/{phone}", PHONE))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Private area")))
			.andExpect(model().size(3))
			.andExpect(model().attribute("account", any(AccountResponse.class)))
			.andExpect(model().attribute("bills", any(List.class)))
			.andExpect(model().attribute("currencies", any(Set.class)))
			.andExpect(view().name("account/private"));
		}
		
		@Test
		void check_security_restriction() throws Exception {
			
			mockMVC.perform(get("/accounts/show/{phone}", "5555555555"))
			.andExpect(status().isForbidden())
			.andExpect(model().size(1))
			.andExpect(model().attribute("message", "Security restricted information"))
			.andExpect(forwardedUrl("/accounts/show/" + PHONE));
		}
		
		@Test
		void can_create_new_bill() throws Exception {
			
			mockMVC.perform(post("/bills/add").with(csrf())
										   .param("phone", PHONE)
										   .param("currency", "SEA")
							)
					.andExpect(status().isCreated())
					.andExpect(jsonPath("$.id").isNumber())
					.andExpect(jsonPath("$.createdAt").exists())
					.andExpect(jsonPath("$.updatedAt").isEmpty())
					.andExpect(jsonPath("$.active").value(true))
					.andExpect(jsonPath("$.balance").value("0.0"))
					.andExpect(jsonPath("$.currency").value("SEA"));
//					.andExpect(jsonPath("$.owner").exists());
		}
		
		@Test
		void can_delete_own_bill() throws Exception {
			
			mockMVC.perform(delete("/bills/delete/{id}", "1").with(csrf()))
					.andExpect(status().isOk());
		}
		
		@Test
		void can_get_payment_html() throws Exception {
			
			mockMVC.perform(post("/bills/operate").with(csrf())
											   .param("id", "1")
											   .param("action", "deposit")
											   .param("balance", "0.00")
						)
				.andExpect(status().isOk())
				.andExpect(model().size(3))
				.andExpect(model().attribute("id", "1"))
				.andExpect(model().attribute("action", "deposit"))
				.andExpect(model().attribute("balance", "0.00"))
				.andExpect(view().name("bill/payment"));
			
			mockMVC.perform(post("/bills/operate").with(csrf())
											   .param("id", "1")
											   .param("action", "withdraw")
											   .param("balance", "0.00")
						)
				.andExpect(status().isOk())
				.andExpect(model().size(3))
				.andExpect(model().attribute("id", "1"))
				.andExpect(model().attribute("action", "withdraw"))
				.andExpect(model().attribute("balance", "0.00"))
				.andExpect(view().name("bill/payment"));
		}

		@Test
		void can_get_transfer_html() throws Exception {
			
			mockMVC.perform(post("/bills/operate").with(csrf())
											   .param("id", "1")
											   .param("action", "transfer")
											   .param("balance", "0.00")
						)
				.andExpect(status().isOk())
				.andExpect(model().size(3))
				.andExpect(model().attribute("id", "1"))
				.andExpect(model().attribute("action", "transfer"))
				.andExpect(model().attribute("balance", "0.00"))
				.andExpect(view().name("bill/transfer"));
		}
		
		@Test
		void check_bill_owner() throws Exception {
			
			mockMVC.perform(get("/bills/validate/{id}", "1"))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.valueOf("text/plain;charset=UTF-8")))
				.andExpect(content().string(equalTo("Admin Adminov")));
			
/*		    HttpHeaders headers = new HttpHeaders();
		    headers.add(HttpHeaders.ACCEPT, MediaType.TEXT_PLAIN_VALUE);
			String response = testRestTemplate.withBasicAuth(PHONE, "supervixen")
					.getForObject("/bills/validate/{id}", String.class, "1");
			assertThat(response).contains("Admin Adminov");*/
		}
		
		@Test
		void owner_not_found() throws Exception {
			
			mockMVC.perform(get("/bills/validate/{id}", "4"))
				.andExpect(status().isNotFound())
				.andExpect(content().contentType(MediaType.valueOf("text/plain;charset=UTF-8")))
				.andExpect(content().string(containsString("Target bill with id: 4 not found")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
										.param("recipient", String.valueOf(777))
//										.param("id", "1")
										.param("action", "transfer")
										.param("balance", "0.00")
										.param("amount", "0.00")
					)
					.andExpect(status().isNotFound())
					.andExpect(model().size(4))
					.andExpect(model().attribute("id", 1))
					.andExpect(model().attribute("action", "transfer"))
					.andExpect(model().attribute("balance", "0.00"))
					.andExpect(model().attribute("message", 
							"Target bill with id: " + 777 + " not found"))
					.andExpect(view().name("bill/transfer"));
		}
		
		@Disabled
		@Test
		void wrong_format_input() throws Exception {
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
										.param("recipient", "XXX")
//									    .param("id", "1")
									    .param("action", "transfer")
									    .param("balance", "10.00")
					)
					.andExpect(status().isBadRequest())
					.andExpect(model().size(4))
					.andExpect(model().attribute("id", 1))
					.andExpect(model().attribute("action", "transfer"))
					.andExpect(model().attribute("balance", "10.00"))
					.andExpect(model().attribute("message", "Please provide correct bill number"))
					.andExpect(view().name("bill/transfer"));
		}

		@Test
		void can_get_password_html() throws Exception {
			
			mockMVC.perform(get("/accounts/password/{phone}", PHONE))
			.andExpect(status().isOk())
			.andExpect(model().size(1))
			.andExpect(model().attribute("password", any(PasswordRequest.class)))
			.andExpect(view().name("account/password"));
		}
		
		@Test
		void success_password_change() throws Exception {
			
			hashPassword();
			
			mockMVC.perform(patch("/accounts/password/{phone}", PHONE).with(csrf())
										.param("oldPassword", "supervixen")
										.param("newPassword", "japanrocks")
					)
					.andExpect(status().isOk())
					.andExpect(model().size(2))
					.andExpect(model().attributeExists("password"))
					.andExpect(model().attribute("success", "Password changed"))
					.andExpect(view().name("account/password"));
		}
		
		@Test
		void failure_password_change() throws Exception {
			
			hashPassword();
			
			mockMVC.perform(patch("/accounts/password/{phone}", PHONE).with(csrf())
										.param("oldPassword", "superjapan")
										.param("newPassword", "vixenrocks")
					)
					.andExpect(status().isBadRequest())
					.andExpect(model().size(2))
					.andExpect(model().attributeExists("password"))
					.andExpect(model().attribute("message", "Old password mismatch"))
					.andExpect(view().name("account/password"));			
		}
		
		@Test
		void password_binding_errors() throws Exception {
			
			mockMVC.perform(patch("/accounts/password/{phone}", PHONE).with(csrf())
										.param("oldPassword", "vixen")
										.param("newPassword", "japan")
					)
					.andExpect(status().isBadRequest())
					.andExpect(model().size(1))
					.andExpect(model().errorCount(2))
					.andExpect(model().attributeExists("password"))
					.andExpect(view().name("account/password"));			
		}
		
		@Test
		void wrong_bill_serial() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.NOT_FOUND_404)
					.withBody("No bill with serial 33 found")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//										.param("id", "1")
									    .param("action", "external")
									    .param("balance", "5.00")
									    .param("amount", "5.00")
									    .param("bank", "Penkov")
									    .param("recipient", "33")
					)
					.andExpect(status().isNotFound())
					.andExpect(model().size(4))
					.andExpect(model().attribute("id", 1))
					.andExpect(model().attribute("action", "external"))
					.andExpect(model().attribute("balance", "5.00"))
					.andExpect(model().attribute("message", "No bill with serial 33 found"))
					.andExpect(view().name("bill/external"));
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));			
		}
		
		@Test
		void wrong_bank_name() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.NOT_FOUND_404)
					.withBody("No bank with name Demo found")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//										.param("id", "1")
									    .param("action", "external")
									    .param("balance", "5.00")
									    .param("amount", "5.00")
									    .param("bank", "Demo")
									    .param("recipient", "22")
					)
					.andExpect(status().isNotFound())
					.andExpect(model().size(4))
					.andExpect(model().attribute("id", 1))
					.andExpect(model().attribute("action", "external"))
					.andExpect(model().attribute("balance", "5.00"))
					.andExpect(model().attribute("message", "No bank with name Demo found"))
					.andExpect(view().name("bill/external"));
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));				
		}
		
		@Test
		void connection_failure() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.SERVICE_UNAVAILABLE_503)
					.withBody("Service is temporary unavailable")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//										.param("id", "1")
									    .param("action", "external")
									    .param("balance", "10.00")
									    .param("amount", "10.00")
									    .param("bank", "Penkov")
									    .param("recipient", "22")
					)
					.andExpect(status().isServiceUnavailable())
					.andExpect(model().size(4))
					.andExpect(model().attribute("id", 1))
					.andExpect(model().attribute("action", "external"))
					.andExpect(model().attribute("balance", "10.00"))
					.andExpect(model().attribute("message", "Service is temporary unavailable"))
					.andExpect(view().name("bill/external"));
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));				
		}
		
		@Test
		void successful_payment() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.OK_200)
					.withBody("Data has been verified")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//									    .param("id", "1")
									    .param("action", "deposit")
									    .param("balance", "100.00")
									    .param("amount", "100.00")
					)
					.andExpect(status().is3xxRedirection())
					.andExpect(redirectedUrl("/accounts/show/" + PHONE));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//									    .param("id", "1")
									    .param("action", "withdraw")
									    .param("balance", "10.00")
									    .param("amount", "10.00")
					)
					.andExpect(status().is3xxRedirection())
					.andExpect(redirectedUrl("/accounts/show/" + PHONE));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//										.param("id", "0")
										.param("action", "transfer")
										.param("balance", "10.00")
										.param("amount", "10.00")
										.param("recipient", "2")
					)
					.andExpect(status().is3xxRedirection())
					.andExpect(redirectedUrl("/accounts/show/" + PHONE));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//				    					.param("id", "1")
									    .param("action", "external")
									    .param("balance", "10.00")
									    .param("amount", "10.00")
									    .param("bank", "Penkov")
									    .param("recipient", "22")
					)
					.andExpect(status().is3xxRedirection())
					.andExpect(flash().attribute("message", "Data has been verified"))
					.andExpect(redirectedUrl("/accounts/show/" + PHONE));
			
			OperationRequest dto = new OperationRequest(777, 2, "USD", 0.01, "Demo");
			mockMVC.perform(post("/bills/external")
										.contentType(MediaType.APPLICATION_JSON)
										.content(mapper.writeValueAsString(dto))
							)
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Successfully received")));
			
			dto = new OperationRequest(777, 3, "NOK", 0.01, "Demo");
		    HttpHeaders headers = new HttpHeaders();
		    headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
			HttpEntity<String> request = new HttpEntity<>(mapper.writeValueAsString(dto), headers);
			ResponseEntity<String> response = testRestTemplate.postForEntity("/bills/external", 
					request, String.class);
			assertThat(response.getStatusCodeValue()).isEqualTo(HttpStatus.OK_200);
			assertThat(response.getBody()).isEqualTo("Successfully received");
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));
		}
		
		@Test
		void zero_amount_exception() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.OK_200)
					.withBody("Data has been verified")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//								    .param("id", "1")
								    .param("action", "deposit")
								    .param("balance", "10.00")
								    .param("amount", "0.00")
				)
				.andExpect(status().isInternalServerError())
				.andExpect(model().size(4))
				.andExpect(model().attribute("id", 1))
				.andExpect(model().attribute("action", "deposit"))
				.andExpect(model().attribute("balance", "10.00"))
				.andExpect(model().attribute("message", "Amount of money should be higher than zero"))
				.andExpect(view().name("bill/payment"));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//								    .param("id", "1")
								    .param("action", "withdraw")
								    .param("balance", "10.00")
								    .param("amount", "0.00")
				)
				.andExpect(status().isInternalServerError())
				.andExpect(model().size(4))
				.andExpect(model().attribute("id", 1))
				.andExpect(model().attribute("action", "withdraw"))
				.andExpect(model().attribute("balance", "10.00"))
				.andExpect(model().attribute("message", "Amount of money should be higher than zero"))
				.andExpect(view().name("bill/payment"));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//									.param("id", "1")
								    .param("action", "external")
								    .param("balance", "10.00")
								    .param("amount", "0.00")
								    .param("bank", "Penkov")
								    .param("recipient", "22")
				)
				.andExpect(status().isInternalServerError())
				.andExpect(model().attribute("id", 1))
				.andExpect(model().attribute("action", "external"))
				.andExpect(model().attribute("balance", "10.00"))
				.andExpect(model().attribute("message", "Amount of money should be higher than zero"))
				.andExpect(view().name("bill/external"));
			
			OperationRequest dto = new OperationRequest(777, 2, "SEA", 0.00, "Demo");
			mockMVC.perform(post("/bills/external").header("Origin", externalURL)
													.contentType(MediaType.APPLICATION_JSON)
													.content(mapper.writeValueAsString(dto))
							)
				.andExpect(status().isBadRequest())
				.andExpect(content().string(containsString("Amount of money should be higher than zero")));
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));
		}
		
		@Test
		void negative_balance_exception() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.OK_200)
					.withBody("Data has been verified")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//								    .param("id", "1")
								    .param("action", "withdraw")
								    .param("balance", "10.00")
								    .param("amount", "10.01")
				)
				.andExpect(status().isInternalServerError())
				.andExpect(model().size(4))
				.andExpect(model().attribute("id", 1))
				.andExpect(model().attribute("action", "withdraw"))
				.andExpect(model().attribute("balance", "10.00"))
				.andExpect(model().attribute("message", "Not enough money to complete operation"))
				.andExpect(view().name("bill/payment"));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//									.param("id", "1")
								    .param("action", "external")
								    .param("balance", "10.00")
								    .param("amount", "10.01")
								    .param("bank", "Penkov")
								    .param("recipient", "22")
				)
				.andExpect(status().isInternalServerError())
				.andExpect(model().size(4))
				.andExpect(model().attribute("id", 1))
				.andExpect(model().attribute("action", "external"))
				.andExpect(model().attribute("balance", "10.00"))
				.andExpect(model().attribute("message", "Not enough money to complete operation"))
				.andExpect(view().name("bill/external"));
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));
		}
		
		@Test
		void same_bill_id_exception() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.OK_200)
					.withBody("Data has been verified")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
				    			.param("recipient", "1")
//							    .param("id", "1")
							    .param("action", "transfer")
							    .param("balance", "10.00")
							    .param("amount", "10.00")
			)
			.andExpect(status().isInternalServerError())
			.andExpect(model().size(4))
			.andExpect(model().attribute("id", 1))
			.andExpect(model().attribute("action", "transfer"))
			.andExpect(model().attribute("balance", "10.00"))
			.andExpect(model().attribute("message", "Source and target bills should not be the same"))
			.andExpect(view().name("bill/transfer"));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//								.param("id", "1")
							    .param("action", "external")
							    .param("balance", "10.00")
							    .param("amount", "5.00")
							    .param("bank", "Penkov")
							    .param("recipient", "1")
			)
			.andExpect(status().isInternalServerError())
			.andExpect(model().size(4))
			.andExpect(model().attribute("id", 1))
			.andExpect(model().attribute("action", "external"))
			.andExpect(model().attribute("balance", "10.00"))
			.andExpect(model().attribute("message", "Source and target bills should not be the same"))
			.andExpect(view().name("bill/external"));
			
			OperationRequest dto = new OperationRequest(777, 777, "SEA", 0.01, "Demo");
			mockMVC.perform(post("/bills/external").header("Origin", externalURL)
													.contentType(MediaType.APPLICATION_JSON)
													.content(mapper.writeValueAsString(dto))
							)
				.andExpect(status().isInternalServerError())
				.andExpect(content().string(containsString("Source and target bills should not be the same")));
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));
		}
		
		@Test
		void currency_mismatch_exception() throws Exception {
			
			wireMockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/verify"))
					.willReturn(WireMock.aResponse()
					.withStatus(HttpStatus.BAD_REQUEST_400)
					.withBody("Wrong currency type NOK for the target bill 22")));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
										.param("recipient", "3")
//										.param("id", "1")
										.param("action", "transfer")
										.param("balance", "10.00")
										.param("amount", "10.00")
					)
					.andExpect(status().isInternalServerError())
					.andExpect(model().size(4))
					.andExpect(model().attribute("id", 1))
					.andExpect(model().attribute("action", "transfer"))
					.andExpect(model().attribute("balance", "10.00"))
					.andExpect(model().attribute("message", "Wrong currency type of the target bill"))
					.andExpect(view().name("bill/transfer"));
			
			mockMVC.perform(patch("/bills/launch/{id}", "1").with(csrf())
//										.param("id", "1")
									    .param("action", "external")
									    .param("balance", "10.00")
									    .param("amount", "0.01")
									    .param("bank", "Penkov")
									    .param("recipient", "22")
					)
					.andExpect(status().isBadRequest())
					.andExpect(model().size(4))
					.andExpect(model().attribute("id", 1))
					.andExpect(model().attribute("action", "external"))
					.andExpect(model().attribute("balance", "10.00"))
					.andExpect(model().attribute("message", "Wrong currency type NOK for the target bill 22"))
					.andExpect(view().name("bill/external"));
			
			OperationRequest dto = new OperationRequest(777, 2, "AUD", 0.01, "Demo");
			mockMVC.perform(post("/bills/external").header("Origin", externalURL)
													.contentType(MediaType.APPLICATION_JSON)
													.content(mapper.writeValueAsString(dto))
							)
				.andExpect(status().isInternalServerError())
				.andExpect(content().string(containsString("Wrong currency type of the target bill")));
			
			wireMockServer.verify(WireMock.exactly(1), 
					WireMock.postRequestedFor(WireMock.urlPathEqualTo("/verify")));
		}
		
		@Test
		void constraint_violation_exception() throws Exception {
			
			OperationRequest dto = new OperationRequest(1_000_000_000, -1, "yuan", -0.01, "Demo");
			mockMVC.perform(post("/bills/external").header("Origin", externalURL)
													.contentType(MediaType.APPLICATION_JSON)
													.content(mapper.writeValueAsString(dto))
							)
				.andExpect(status().isBadRequest())
				.andExpect(content().string(containsString("Sender's bill number should be less than 10 digits length")))
				.andExpect(content().string(containsString("Recepient's bill number should be positive")))
				.andExpect(content().string(containsString("Currency code should be 3 capital characters length")))
				.andExpect(content().string(containsString("Amount of money should be higher than zero")));
			
			dto = new OperationRequest(null, null, " ", null, null);
			mockMVC.perform(post("/bills/external").header("Origin", externalURL)
													.contentType(MediaType.APPLICATION_JSON)
													.content(mapper.writeValueAsString(dto))
							)
				.andExpect(status().isBadRequest())
				.andExpect(content().string(containsString("Sender must not be null")))
				.andExpect(content().string(containsString("Recepient must not be null")))
				.andExpect(content().string(containsString("Currency must not be blank")))
				.andExpect(content().string(containsString("Amount must not be null")))
				.andExpect(content().string(containsString("Bank name must not be blank")));
		}
		
		@Test
		void establish_emitter() throws Exception {
//			mockMVC.perform(get("/bills/notify")).andExpect(status().isCreated());
			mockMVC.perform(get("/bills/notify")).andExpect(status().isOk());
/*			ResponseBodyEmitter emitter = testRestTemplate.getForObject(("/bills/notify"), 
					ResponseBodyEmitter.class);
			assertThat(emitter).isNotNull();*/
		}
		
		@WithMockUser
		@Test
		void check_cors_and_xml_support() throws Exception {
			
			mockMVC.perform(options("/bills/external").header("Origin", externalURL))
				.andExpect(status().isOk());
			
			mockMVC.perform(post("/bills/external").header("Origin", externalURL)
													.contentType(MediaType.APPLICATION_XML))
				.andExpect(status().isBadRequest());
			
			mockMVC.perform(post("/bills/external").header("Origin", "http://evildevil.com")
													.contentType(MediaType.APPLICATION_XML))
				.andExpect(status().isForbidden());
			
			mockMVC.perform(get("/bills/notify").header("Origin", externalURL))
				.andExpect(status().isForbidden());
			
			mockMVC.perform(post("/bills/external").header("Origin", externalURL))
				.andExpect(status().isUnsupportedMediaType());
			
			XmlMapper xmlMapper = new XmlMapper();
			OperationRequest dto = new OperationRequest(777, 2, "USD", 0.01, "Demo");
			mockMVC.perform(post("/bills/external").header("Origin", externalURL)
													.accept(MediaType.APPLICATION_XML)
													.contentType(MediaType.APPLICATION_XML)
													.content(xmlMapper.writeValueAsString(dto))
							)
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_XML))
				.andExpect(content().string(containsString("Successfully received")));
		}
				
		@AfterEach
		void tear_down() {
			wireMockServer.resetAll();
		}
		
	}
	
	@WithMockUser(username = "0000000000", roles = "ADMIN")
	@Nested
	class MegaControllerIT{
		
	    @Autowired
	    ApplicationContext context;
		
		@Test
		void can_change_implementation() throws Exception {

			AccountDetailsService details = (AccountDetailsService) context.getBean("accountDetailsService");
			LoginListener listener = (LoginListener) context.getBean("loginListener");
			UnlockService unlock = (UnlockService) context.getBean("unlockService");
			
			String impl = "DAO";			
			mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
				.andExpect(status().isOk())
				.andExpect(content()
					.string(containsString("Services impementation has been switched to " + impl)));			
			assertThat(context.getBean("accountServiceAlias")).isInstanceOf(AccountServiceDAO.class);
			assertThat(context.getBean("billServiceAlias")).isInstanceOf(BillServiceDAO.class);
			assertThat(context.getBean("operationServiceAlias")).isInstanceOf(OperationServiceDAO.class);
			assertThat(details.getImpl()).isEqualTo("DAO");
			assertThat(listener.getImpl()).isEqualTo("DAO");
			assertThat(unlock.getImpl()).isEqualTo("DAO");

			impl = "JPA";
			mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
				.andExpect(status().isOk())
				.andExpect(content()
					.string(containsString("Services impementation has been switched to " + impl)));
			assertThat(context.getBean("accountServiceAlias")).isInstanceOf(AccountServiceJPA.class);
			assertThat(context.getBean("billServiceAlias")).isInstanceOf(BillServiceJPA.class);
			assertThat(context.getBean("operationServiceAlias")).isInstanceOf(OperationServiceJPA.class);
			assertThat(details.getImpl()).isEqualTo("JPA");
			assertThat(listener.getImpl()).isEqualTo("JPA");
			assertThat(unlock.getImpl()).isEqualTo("JPA");
		}
				
		@Test
		void wrong_implementation_type() throws Exception {
			
			String impl = "XXX";
			mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
					.andExpect(status().isBadRequest())
					.andExpect(content()
						.string(containsString("Wrong implementation type " + impl + " specified, retry")));
		}
		
		@WithMockUser(username = "1111111111", roles = "CLIENT")
		@Test
		void credentials_forbidden() throws Exception {
			
	        mockMVC.perform(put("/control"))
				.andExpect(status().isForbidden());
		}
		
	}
	
	@AfterAll
	static void clear() {
		wireMockServer.stop();
	}
	
}
