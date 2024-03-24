package com.github.irybov.bankdemomvc.controller;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.zip.GZIPOutputStream;

import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.irybov.bankdemomvc.controller.AdminController;
import com.github.irybov.bankdemomvc.controller.dto.AccountResponse;
import com.github.irybov.bankdemomvc.controller.dto.BillResponse;
import com.github.irybov.bankdemomvc.controller.dto.OperationResponse;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.entity.Bill;
import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.security.AccountDetailsService;
import com.github.irybov.bankdemomvc.service.AccountService;
import com.github.irybov.bankdemomvc.service.BillService;
import com.github.irybov.bankdemomvc.service.OperationService;
import com.opencsv.CSVWriter;

@WithMockUser(username = "0000000000", roles = "ADMIN")
@WebMvcTest(controllers = AdminController.class)
@Import(BCryptConfig.class)
class AdminControllerTest {

	@MockBean
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
	@MockBean
	@Qualifier("billServiceAlias")
	private BillService billService;
	@MockBean
	@Qualifier("operationServiceAlias")
	private OperationService operationService;
	@MockBean
	private UserDetailsService accountDetailsService;
	@Autowired
	private MockMvc mockMVC;
	@Autowired
	private ObjectMapper mapper;
	
	private Authentication authentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}
	private String phone;
	
	private static Account entity;
	
	@SpyBean
	private ModelMapper modelMapper;
	
	@TestConfiguration
	static class ExecutorConfig {
	
		@Bean
	    @Primary
	    public Executor asyncExecutor() {
	    	final int cores = Runtime.getRuntime().availableProcessors();
	    	final ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
	    	executor.setCorePoolSize(cores);
	        executor.setMaxPoolSize(cores * 2);
	        executor.setQueueCapacity(cores * 4);
	    	executor.initialize();
	    	return executor;
	    }
		
	}

	@BeforeAll
	static void prepare() {
		
		entity = new Account
				("Admin", "Adminov", "0000000000", LocalDate.of(2001, 01, 01), "superadmin", true);
		entity.setCreatedAt(OffsetDateTime.now());
		entity.setUpdatedAt(OffsetDateTime.now());
		entity.setId(0);
		
//		modelMapper = new ModelMapper();
	}
	
	@BeforeEach
	void set_up() {
		phone = authentication().getName();		
	}

    @Test
	void can_get_admin_html() throws Exception {

		AccountResponse account = modelMapper.map(entity, AccountResponse.class);		
		when(accountService.getAccountDTO(anyString())).thenReturn(account);
		
		mockMVC.perform(get("/accounts/search"))
			.andExpect(status().isOk())
			.andExpect(model().size(1))
	        .andExpect(model().attribute("account", account))
			.andExpect(content().string(containsString("Admin's area")))
	        .andExpect(view().name("account/search"));
		
	    verify(accountService).getAccountDTO(anyString());
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
		
		List<AccountResponse> clients = new ArrayList<>();
		Account entity = new Account("Admin", "Adminov", "0000000000", LocalDate.of(2001, 01, 01),
				 BCrypt.hashpw("superadmin", BCrypt.gensalt(4)), true);
		clients.add(modelMapper.map(entity, AccountResponse.class));
		when(accountService.getAll()).thenReturn(clients);
		
		byte[] output = data_2_gzip_converter(clients);
		
		MvcResult result = mockMVC.perform(get("/accounts/list/all"))
			.andExpect(request().asyncStarted())
			.andReturn();
			
		mockMVC.perform(asyncDispatch(result))
			.andExpect(status().isOk())
			.andExpect(content().contentType(MediaType.APPLICATION_OCTET_STREAM_VALUE))
			.andExpect(content().bytes(output));
		
	    verify(accountService).getAll();
	}
	private byte[] data_2_gzip_converter(List<AccountResponse> clients) {
		
		String json = null;
		try {
			json = mapper.writeValueAsString(clients);
		}
		catch (JsonProcessingException exc) {
//			log.error(exc.getMessage(), exc);
		}
		
		byte[] data = json.getBytes(StandardCharsets.UTF_8);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try(OutputStream gzip = new GZIPOutputStream(baos);){
			gzip.write(data);
			gzip.flush();
		}
		catch (IOException exc) {
//			log.error(exc.getMessage(), exc);
		}
		byte[] bytes = baos.toByteArray();
		try {
			baos.flush();
			baos.close();
		}
		catch (IOException exc) {
//			log.error(exc.getMessage(), exc);
		}
		
		return bytes;
	}
	
	@Test
	void clients_not_found_exception() throws Exception {
		
		when(accountService.getAll()).thenReturn(new ArrayList<AccountResponse>());
		
		MvcResult result = mockMVC.perform(get("/accounts/list/all"))
			.andExpect(request().asyncStarted())
			.andReturn();
			
		mockMVC.perform(asyncDispatch(result))
			.andExpect(status().isInternalServerError());
		
		
		when(accountService.getAll()).thenReturn(null);
		
		result = mockMVC.perform(get("/accounts/list/all"))
			.andExpect(request().asyncStarted())
			.andReturn();
			
		mockMVC.perform(asyncDispatch(result))
			.andExpect(status().isInternalServerError());
		
		
	    verify(accountService, times(2)).getAll();
	}
	
	@Test
	void can_change_account_status() throws Exception {
		
		when(accountService.changeStatus(anyInt())).thenReturn(false);		
		
		mockMVC.perform(patch("/accounts/status/{id}", "0").with(csrf()))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("false")));
		
	    verify(accountService).changeStatus(anyInt());
	}
	
	@Test
	void can_change_bill_status() throws Exception {
		
		when(billService.changeStatus(anyInt())).thenReturn(false);
		
		mockMVC.perform(patch("/bills/status/{id}", "0").with(csrf()))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("false")));
		
	    verify(billService).changeStatus(anyInt());
	}
	
	@Test
	void input_mismatch_exception() throws Exception {
		
/*		assertThatThrownBy(() -> mockMVC.perform(get("/accounts/search/{phone}", "XXL"))
				.andExpect(status().isInternalServerError()))
				.hasCause(new InputMismatchException("Phone number should be of 10 digits"));*/
		
		mockMVC.perform(get("/accounts/search/{phone}", "XXL"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.report").value("Phone number should be of 10 digits"));
	}
	
	@Test
	void account_not_found_exception() throws Exception {
		
		String wrong = "9999999999";
//		when(accountService.getAccountDTO(wrong))
		when(accountService.getFullDTO(wrong))
			.thenThrow(new PersistenceException("Account with phone " + wrong + " not found"));
		
		mockMVC.perform(get("/accounts/search/{phone}", wrong))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.report").value("Account with phone " + wrong + " not found"));
		
//	    verify(accountService).getAccountDTO(wrong);
	    verify(accountService).getFullDTO(wrong);
	}
	
	@Test
	void can_get_account_info() throws Exception {
		
		AccountResponse account = modelMapper.map(entity, AccountResponse.class);
		List<BillResponse> bills = new ArrayList<>();
		Bill bill = new Bill("SEA", true, entity);
//		bill.setOwner(entity);
		bills.add(modelMapper.map(bill, BillResponse.class));
		account.setBills(bills);
//		when(accountService.getAccountDTO(phone)).thenReturn(account);
		when(accountService.getFullDTO(phone)).thenReturn(account);
//		when(accountService.getBills(anyInt())).thenReturn(bills);
		
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
		
//	    verify(accountService).getAccountDTO(phone);
//	    verify(accountService).getBills(anyInt());
	    verify(accountService).getFullDTO(phone);
	}
	
	@Test
	void can_get_operations_page() throws Exception {
		
		List<OperationResponse> operations = new ArrayList<>();
		operations.add(modelMapper.map(new Operation(), OperationResponse.class));
//		OperationPage page = new OperationPage();
//		Pageable pageable = PageRequest.of(page.getPageNumber(), page.getPageSize(),
//										   page.getSortDirection(), page.getSortBy());
		Page<OperationResponse> operationPage = new PageImpl<>(operations);
		
		when(operationService.getPage(anyInt(), anyString(), anyDouble(), anyDouble(),
				any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class)))
				.thenReturn(operationPage);
		
		mockMVC.perform(get("/operations/list/{id}", "0"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.pageable").exists())
			.andExpect(jsonPath("$.sort").exists())
			.andExpect(jsonPath("$.content").isArray())
			.andExpect(jsonPath("$.content").isNotEmpty());
		
		verify(operationService).getPage(anyInt(), anyString(), anyDouble(), anyDouble(),
				any(OffsetDateTime.class), any(OffsetDateTime.class), any(Pageable.class));
	}
	
	@Test
	void can_export_data_2_csv_file() throws Exception {
		
		List<OperationResponse> operations = new ArrayList<>();
		Operation operation = Operation.builder()
				.amount(0.00)
				.action("infernal")
				.currency("SEA")
				.recipient(0)
				.createdAt(OffsetDateTime.now())
				.bank("Demo")
				.build();
		operations.add(modelMapper.map(operation, OperationResponse.class));

		Bill fake = new Bill("SEA", true, entity);
		fake.setBalance(BigDecimal.valueOf(9.99));
		fake.setCreatedAt(OffsetDateTime.now());
		BillResponse bill = modelMapper.map(fake, BillResponse.class);
		
		CompletableFuture<List<OperationResponse>> futureOperations =
				CompletableFuture.completedFuture(operations);
		when(operationService.getAll(anyInt())).thenReturn(futureOperations.join());
		CompletableFuture<BillResponse> futureBill = CompletableFuture.completedFuture(bill);
		when(billService.getBillDTO(anyInt())).thenReturn(futureBill.join());

		CompletableFuture<byte[]> futureByteArray = CompletableFuture.completedFuture
				(data_2_csv_converter(futureBill.join(), futureOperations.join()));
		
		MvcResult result = mockMVC.perform(get("/operations/print/{id}", "0"))
			.andExpect(request().asyncStarted())
			.andReturn();
		
		mockMVC.perform(asyncDispatch(result))
			.andExpect(status().isCreated())
			.andExpect(content().contentType(MediaType.APPLICATION_OCTET_STREAM_VALUE))
			.andExpect(content().bytes(futureByteArray.join()));
		
		verify(operationService).getAll(anyInt());
		verify(billService).getBillDTO(anyInt());
	}	
	private byte[] data_2_csv_converter(BillResponse bill, List<OperationResponse> operations) {

		AccountResponse account = bill.getOwner();
		
		String[] owner = {account.getName(), account.getSurname(), account.getPhone()};		
		List<String[]> data = new ArrayList<>();
		data.add(owner);
		data.add(new String[0]);
		
		String[] info = {bill.getCurrency(), String.valueOf(bill.getBalance()), bill.getCreatedAt()
				.toString()};
		data.add(info);
		data.add(new String[0]);
		
		String[] header = {"Action", "Amount", "When", "Recipient", "Sender", "Bank"};
		data.add(header);
//		data.add(new String[0]);		
		
		for(OperationResponse operation : operations) {
			String[] row = {operation.getAction(),
							String.valueOf(operation.getAmount()),
							operation.getCreatedAt().toString(),
							String.valueOf(operation.getRecipient()),
							String.valueOf(operation.getSender()),
							operation.getBank()};
			data.add(row);
		}
		
		byte[] byteArray = null;
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				OutputStreamWriter osw = new OutputStreamWriter(baos);
				PrintWriter pw = new PrintWriter(osw);
				BufferedWriter bw = new BufferedWriter(pw);
				CSVWriter writer = new CSVWriter(bw);) {
			writer.writeAll(data);
			writer.flush();
			byteArray = baos.toByteArray();
		}
		catch (IOException exc) {
//			log.error(exc.getMessage(), exc);
		}
		
		return byteArray;
	}
	
	@Test
	void data_on_fetch_exception() throws Exception {
		
		List<OperationResponse> operations = new ArrayList<>();
		
		CompletableFuture<List<OperationResponse>> futureOperations =
				CompletableFuture.completedFuture(operations);
		when(operationService.getAll(anyInt())).thenReturn(futureOperations.join());
		when(billService.getBillDTO(anyInt())).thenThrow(new EntityNotFoundException());
//		CompletableFuture<BillResponse> futureBill = CompletableFuture.completedFuture(null);
		
		MvcResult result = mockMVC.perform(get("/operations/print/{id}", "0"))
			.andExpect(request().asyncStarted())
			.andReturn();
			
		mockMVC.perform(asyncDispatch(result))
			.andExpect(status().isInternalServerError())
			.andExpect(content().bytes(new byte[0]));
			
		verify(operationService).getAll(anyInt());
		verify(billService).getBillDTO(anyInt());
	}
	
	@AfterEach
	void tear_down() {
		phone = null;
	}
	
	@AfterAll
	static void clear() {
		entity = null;
//		modelMapper = null;
	}
	
}
