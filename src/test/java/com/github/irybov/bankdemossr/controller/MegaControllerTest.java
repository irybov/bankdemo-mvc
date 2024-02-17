package com.github.irybov.bankdemossr.controller;

import static org.hamcrest.CoreMatchers.any;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.github.irybov.bankdemossr.controller.MegaController;
import com.github.irybov.bankdemossr.dao.AccountDAO;
import com.github.irybov.bankdemossr.jpa.AccountJPA;
import com.github.irybov.bankdemossr.security.AccountDetailsService;
import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.service.AccountServiceDAO;
import com.github.irybov.bankdemossr.service.AccountServiceJPA;

@Disabled
@WebMvcTest(controllers = MegaController.class)
@WithMockUser(username = "0000000000", roles = "ADMIN")
//@Import(value = {AccountServiceJPA.class, AccountServiceDAO.class})
class MegaControllerTest {

	@MockBean
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
	@MockBean
	private AccountServiceJPA accountServiceJPA;
	@MockBean
	private AccountServiceDAO accountServiceDAO;
	@MockBean
	ApplicationContext context;
	@MockBean
	UserDetailsService accountDetailsService;
	@Autowired
	private MockMvc mockMVC;
	
	@TestConfiguration
	static class TestConfig {
		
		@Bean
		@Primary
		public BCryptPasswordEncoder passwordEncoder() {
		    return new BCryptPasswordEncoder(4);
		}
		
	}
	
	@Test
	void can_change_implementation() throws Exception {

		String impl = "DAO";
//		String bean = accountService.getClass().getSimpleName();
		when(context.getBean("accountServiceDAO")).thenReturn(accountServiceDAO);
		mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
				.andExpect(status().isOk())
				.andExpect(content()
					.string(containsString("Services impementation has been switched to " + impl)));
		verify(context).getBean(anyString());
		
		impl = "JPA";
//		bean = accountService.getClass().getSimpleName();
		when(context.getBean("accountServiceJPA")).thenReturn(accountServiceJPA);
		mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
				.andExpect(status().isOk())
				.andExpect(content()
					.string(containsString("Services impementation has been switched to " + impl)));
		verify(context).getBean(anyString());
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
