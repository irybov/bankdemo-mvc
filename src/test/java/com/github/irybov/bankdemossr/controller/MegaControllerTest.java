package com.github.irybov.bankdemossr.controller;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.github.irybov.bankdemossr.controller.AdminController;
import com.github.irybov.bankdemossr.controller.AuthController;
import com.github.irybov.bankdemossr.controller.BankController;
import com.github.irybov.bankdemossr.controller.MegaController;
import com.github.irybov.bankdemossr.security.AccountDetailsService;

@WebMvcTest(controllers = MegaController.class)
@WithMockUser(username = "0000000000", roles = "ADMIN")
class MegaControllerTest {

	@MockBean
	private AuthController auth;
	@MockBean
	private AdminController admin;
	@MockBean
	private BankController bank;
	@MockBean
	private AccountDetailsService details;
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
	void can_change_implementations() throws Exception {

		String impl = "DAO";
		String bean = "accountServiceDAO";
//		doNothing().when(details).setServiceImpl(impl);
		when(details.setServiceImpl(impl)).thenReturn(bean);
		mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
				.andExpect(status().isOk())
				.andExpect(content()
					.string(containsString("Services impementation has been switched to " + bean)));
		
		impl = "JPA";
		bean = "accountServicePJA";
//		doNothing().when(details).setServiceImpl(impl);
		when(details.setServiceImpl(impl)).thenReturn(bean);
		mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
				.andExpect(status().isOk())
				.andExpect(content()
					.string(containsString("Services impementation has been switched to " + bean)));
	}
	
	@Test
	void wrong_implementation_type() throws Exception {
		
		String impl = "XXX";
		mockMVC.perform(put("/control").with(csrf()).param("impl", impl))
				.andExpect(status().isBadRequest())
				.andExpect(content()
					.string(containsString("Wrong implementation type specified, retry")));
	}

	@WithMockUser(username = "1111111111", roles = "CLIENT")
	@Test
	void credentials_forbidden() throws Exception {
		
        mockMVC.perform(get("/control"))
			.andExpect(status().isForbidden());
	}
	
}
