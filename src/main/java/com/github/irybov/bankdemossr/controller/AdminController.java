package com.github.irybov.bankdemossr.controller;

import java.io.BufferedInputStream;
//import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileNotFoundException;
//import java.io.FileOutputStream;
//import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
//import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
//import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
//import java.nio.file.FileSystems;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;
//import java.util.concurrent.ExecutorService;
//import java.util.concurrent.Executors;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceException;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.InputStreamResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
//import org.springframework.ui.ModelMap;
//import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
//import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.irybov.bankdemossr.controller.dto.AccountResponse;
import com.github.irybov.bankdemossr.controller.dto.BillResponse;
import com.github.irybov.bankdemossr.controller.dto.OperationResponse;
import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.service.BillService;
import com.github.irybov.bankdemossr.service.OperationService;
import com.opencsv.CSVWriter;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

@Api(description = "Controller for admin's actions ")
@Slf4j
//@Validated
@Controller
@PreAuthorize("hasRole('ADMIN')")
public class AdminController extends BaseController {

	@Autowired
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
	@Autowired
	@Qualifier("billServiceAlias")
	private BillService billService;
	@Autowired
	@Qualifier("operationServiceAlias")
	private OperationService operationService;
	
	private final Executor executorService;
	public AdminController(Executor executorService) {
		this.executorService = executorService;
	}
	
	@ApiOperation("Returns admin's working html-page")
	@GetMapping("/accounts/search")
	public String getAdminPage(@RequestParam(required = false) String phone, Model model) {
		
		AccountResponse account;
		try {
			account = accountService.getAccountDTO(authentication().getName());
			model.addAttribute("account", account);
			log.info("Admin {} has enter admin's zone", account.getPhone());
		}
		catch (PersistenceException exc) {
			log.error(exc.getMessage(), exc);
		}
/*		AccountResponseDTO target = null;
		try {
			target = accountService.getAccountDTO(phone);
		}
		catch (Exception exc) {
			if(phone != null) {
				modelMap.addAttribute("message", "Account with number: " + phone + " not found");
			}
		}
		finally {
			modelMap.addAttribute("admin", admin);
			modelMap.addAttribute("target", target);
		}*/
		return "account/search";
	}
	
	@ApiOperation("Returns information about client")
	@GetMapping("/accounts/search/{phone}")
	public ResponseEntity<?> searchAccount(@PathVariable String phone) {
		
		if(phone != null) {
			if(!phone.matches("^\\d{10}$")) {
				log.warn("Admin {} types phone {} in a wrong format",
								  authentication().getName(), phone);
				String message = new String("Phone number should be of 10 digits");
				
				Map<String, String> map = Stream.of(new String[][] {{"report", message},})
								.collect(Collectors.toMap(data -> data[0], data -> data[1]));
				String json = null;
				try {
					json = mapper.writeValueAsString(map);
				}
				catch (JsonProcessingException jpe) {
					log.error(jpe.getMessage(), jpe);
				}
				return new ResponseEntity<String>(json, HttpStatus.BAD_REQUEST);
			}
		}
		
		AccountResponse target = null;
		try {
//			target = accountService.getAccountDTO(phone);
			target = accountService.getFullDTO(phone);
//			List<BillResponseDTO> bills = accountService.getBills(target.getId());
//			target.setBills(bills);
			log.info("Admin {} requests data about client {}", authentication().getName(), phone);
			return new ResponseEntity<AccountResponse>(target, HttpStatus.OK);
		}
		catch (PersistenceException exc) {
			log.error("Database exception: account with phone {} not found", phone, exc);
			
			Map<String, String> map = Stream.of(new String[][] {{"report", exc.getMessage()},})
							.collect(Collectors.toMap(data -> data[0], data -> data[1]));
			String json = null;
			try {
				json = mapper.writeValueAsString(map);
			}
			catch (JsonProcessingException jpe) {
				log.error(jpe.getMessage(), jpe);
			}
			return new ResponseEntity<String>(json, HttpStatus.NOT_FOUND);
//			return new ResponseEntity<String>(message, HttpStatus.NOT_FOUND);
		}
/*		if(target == null) {
			log.error("Database exception: " + phone + " not found");
			throw new EntityNotFoundException("Database exception: " + phone + " not found");
		}*/
//		List<BillResponseDTO> bills = accountService.getBills(target.getId());
//		target.setBills(bills);
//		return target;
//		return new ResponseEntity<>(target, HttpStatus.OK);
	}

	@ApiOperation("Returns clients html-page")
	@GetMapping("/accounts/list")
	public String getClientsPage(){
//	public String getClients(Model model){
//		List<AccountResponseDTO> clients = accountService.getAll();
//		model.addAttribute("clients", clients);
		return "account/clients";
	}
	@ApiOperation("Returns list of all clients")
	@GetMapping("/accounts/list/all")
	public CompletableFuture<ResponseEntity<byte[]>> getClientsList(){
		
		List<AccountResponse> clients = accountService.getAll();
		if(clients == null || clients.isEmpty()) {
			return CompletableFuture.completedFuture(ResponseEntity.internalServerError().build());
		}
		byte[] bytes = data_2_gzip_converter(clients);
		
		return CompletableFuture.supplyAsync(() -> 
				ResponseEntity.ok().header(HttpHeaders.CONTENT_ENCODING, "gzip").body(bytes), 
				executorService);
	}
	private byte[] data_2_gzip_converter(List<AccountResponse> clients) {
		
		String json = null;
		try {
			json = mapper.writeValueAsString(clients);
		}
		catch (JsonProcessingException exc) {
			log.error(exc.getMessage(), exc);
		}
		
		byte[] data = json.getBytes(StandardCharsets.UTF_8);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try(OutputStream gzip = new GZIPOutputStream(baos);){
			gzip.write(data);
			gzip.flush();
		}
		catch (IOException exc) {
			log.error(exc.getMessage(), exc);
		}
		byte[] bytes = baos.toByteArray();
		try {
			baos.flush();
			baos.close();
		}
		catch (IOException exc) {
			log.error(exc.getMessage(), exc);
		}
		
		return bytes;
	}
	
	/*	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/accounts/list/{pageNumber}")
	@ResponseBody
	public List<AccountResponseDTO> getClients(@PathVariable int pageNumber){
		return accountService.getAll(pageNumber);
	}*/
	
/*	@PreAuthorize("hasRole('ADMIN')")
	@PatchMapping("/accounts/status/{phone}")
	public String changeAccountStatus(@PathVariable String phone, ModelMap modelMap) {
		
		accountService.changeStatus(phone);
		return searchAccount(phone, modelMap);
	}*/
	@ApiOperation("Changes client status")
	@PatchMapping("/accounts/status/{id}")
	@ResponseBody
	public String changeAccountStatus(@PathVariable int id) {		
		Boolean status = null;
		status = accountService.changeStatus(id);
		log.info("Admin {} changes active status of client {} to {}",
							 authentication().getName(), id, status);
		return status.toString();
	}
	
/*	@PreAuthorize("hasRole('ADMIN')")
	@PatchMapping("/bills/status/{phone}")
	public String changeBillStatus(@PathVariable String phone, @RequestParam int id,
			ModelMap modelMap) {
		
		try {
			billService.changeStatus(id);
		} catch (Exception exc) {
			exc.printStackTrace();
		}
		return searchAccount(phone, modelMap);
	}*/	
	@ApiOperation("Changes bill status")
	@PatchMapping("/bills/status/{id}")
	@ResponseBody
	public String changeBillStatus(@PathVariable int id) {
		
		Boolean status = null;
		status = billService.changeStatus(id);
		log.info("Admin {} changes active status of bill {} to {}",
						   authentication().getName(), id, status);
		return status.toString();
	}
	
/*	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/operations/list")
	public String showOperations(@RequestParam String phone, @RequestParam int id,
			ModelMap modelMap) {
		
		List<OperationResponseDTO> operations = operationService.getAll(id);
		modelMap.addAttribute("operations", operations);
		modelMap.addAttribute("phone", phone);
		return searchAccount(phone, modelMap);
	}*/	
/*	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/operations/list/{id}")
	@ResponseBody
	public List<OperationResponseDTO> getOperations(@PathVariable int id) {
		List<OperationResponseDTO> operations = operationService.getAll(id);
		return operations;
	}*/
	
	@ApiOperation("Returns bill's operations history html-page")
	@GetMapping("/operations/list")
	public String getOperationsPage() {
		return "account/history";
	}
	@ApiOperation("Returns filtered pageable list of bill's operations")
	@GetMapping("/operations/list/{id}")
	@ResponseBody
	public Page<OperationResponse> getOperationsList(@PathVariable int id,
			@RequestParam Optional<String> mindate, @RequestParam Optional<String> maxdate,
			@RequestParam Optional<Double> minval, @RequestParam Optional<Double> maxval,
			@RequestParam Optional<String> action, Pageable pageable) {
		
		final String FROM = mindate.orElse("1900-01-01");
		final String TO = maxdate.orElse(LocalDate.now().toString());
		LocalDate from = LocalDate.parse(FROM.isEmpty() ? "1900-01-01" : FROM);
		LocalDate to = LocalDate.parse(TO.isEmpty() ? LocalDate.now().toString() : TO);
		
		OffsetDateTime dateFrom = OffsetDateTime.of(from, LocalTime.MIN, ZoneOffset.UTC);
		OffsetDateTime dateTo = OffsetDateTime.of(to, LocalTime.MAX, ZoneOffset.UTC);
		
//		OperationPage page = new OperationPage();
//		page.setPageNumber(pageable.getPageNumber());
//		page.setPageSize(pageable.getPageSize());
		
		log.info("Admin {} requests list of operations with bill {}",
									 authentication().getName(), id);
		
		return operationService.getPage(id, action.orElse("_"),
				minval.orElse(0.01), maxval.orElse(10000.00), dateFrom, dateTo, pageable);
	}
	
	@ApiOperation("Exports bill's operations list to CSV file")
//	@GetMapping("/operations/print/{id}")
	@GetMapping(value = "/operations/print/{id}", 
				produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	@ResponseBody
//	public void export2csv(@PathVariable int id, HttpServletResponse response) throws IOException {
	public CompletableFuture<InputStreamResource> export2csv(@PathVariable int id, 
			HttpServletResponse response) {

		CompletableFuture<List<OperationResponse>> futureOperations =
				CompletableFuture.supplyAsync(() -> operationService.getAll(id), executorService);
		CompletableFuture<BillResponse> futureBill = CompletableFuture.supplyAsync
				(() -> {try {return billService.getBillDTO(id);}
					   	catch(EntityNotFoundException exc) {
					   		log.error(exc.getMessage(), exc);
					   		return null;
					   	}
					}, executorService);
		
/*		final String SLASH = FileSystems.getDefault().getSeparator();
		final String PATH = System.getProperty("user.dir") + SLASH + "files";
		new File(PATH).mkdir();
		final String FILENAME = "Bill-" + id +".csv";*/
		
/*		try {futureBill.get();}
		catch (InterruptedException | ExecutionException exc) {
			futureOperations.complete(null);
			log.error(exc.getMessage(), exc);
	   		response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
	   		return CompletableFuture.completedFuture(null);
		}*/
		CompletableFuture<byte[]> futureByteArray = CompletableFuture.supplyAsync
				(() -> {
					try {return data_2_csv_converter(futureBill.join(), futureOperations.join());}
					catch (Exception exc) {
						log.error(exc.getMessage(), exc);
						response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
						return null;
					}
				}, executorService);

		
/*        try (CSVWriter writer = new CSVWriter(new BufferedWriter(new FileWriter
        		(new File(PATH, FILENAME))))) {
            writer.writeAll(data);
        }
        catch (IOException exc) {
        	log.error(exc.getMessage(), exc);
		}*/
		response.setStatus(HttpServletResponse.SC_CREATED);
		log.info("Admin {} exports data about bill {} to csv", authentication().getName(), id);		
        return CompletableFuture.supplyAsync(() -> 
        					new InputStreamResource(new BufferedInputStream(
        					new ByteArrayInputStream(futureByteArray.join()))), executorService)
	        		.exceptionally(exc -> null);
        
//		File file = new File(PATH + SLASH + FILENAME);
//		return new InputStreamResource(new BufferedInputStream(new FileInputStream(file)));
/*        response.setContentType("text/csv");
        response.setContentLength((int)file.length());
        response.setHeader("Content-Disposition", "attachment; filename="+FILENAME+"");
        response.getWriter().print(file);*/
	}
	private byte[] data_2_csv_converter(BillResponse bill, List<OperationResponse> operations) throws Exception {

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
				Writer osw = new OutputStreamWriter(baos);
				Writer pw = new PrintWriter(osw);
				Writer bw = new BufferedWriter(pw);
				CSVWriter writer = new CSVWriter(bw);) {
			writer.writeAll(data);
			writer.flush();
			byteArray = baos.toByteArray();
		}
/*		catch (IOException exc) {
			log.error(exc.getMessage(), exc);
		}
		*/
		return byteArray;		
	}
	
}
