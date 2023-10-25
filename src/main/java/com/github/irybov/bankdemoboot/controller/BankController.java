package com.github.irybov.bankdemoboot.controller;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.util.ArrayList;
import java.util.Currency;
import java.util.HashSet;
import java.util.List;
//import java.util.EnumSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

import javax.annotation.PostConstruct;
import javax.persistence.EntityNotFoundException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolation;
import javax.validation.Valid;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
//import org.springframework.data.domain.Page;
//import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
//import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.UnknownHttpStatusCodeException;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.fasterxml.jackson.core.JsonProcessingException;
//import com.github.irybov.bankdemoboot.Currency;
import com.github.irybov.bankdemoboot.controller.dto.AccountResponse;
import com.github.irybov.bankdemoboot.controller.dto.BillResponse;
import com.github.irybov.bankdemoboot.controller.dto.OperationRequest;
import com.github.irybov.bankdemoboot.controller.dto.PasswordRequest;
import com.github.irybov.bankdemoboot.entity.Operation;
import com.github.irybov.bankdemoboot.misc.Action;
import com.github.irybov.bankdemoboot.misc.EmitterPayload;
import com.github.irybov.bankdemoboot.service.OperationService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.extern.slf4j.Slf4j;
import springfox.documentation.annotations.ApiIgnore;

import com.github.irybov.bankdemoboot.service.AccountService;
import com.github.irybov.bankdemoboot.service.BillService;

@Api(description = "Controller for client's actions")
@CrossOrigin(origins="http://"+"${server.address}"+":"+"${server.port}", allowCredentials="true")
@Slf4j
//@Validated
@Controller
public class BankController extends BaseController {

	@Autowired
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
	@Autowired
	@Qualifier("billServiceAlias")
	private BillService billService;
	@Autowired
	@Qualifier("operationServiceAlias")
	private OperationService operationService;
	
	@Autowired
	private RestTemplate restTemplate;
	
	private final Executor executorService;
	public BankController(Executor executorService) {
		this.executorService = executorService;
	}

	private Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();
	
	@Value("${external.payment-service}")
	private String externalURL;
	
	private Set<Currency> currencies = new HashSet<>();
	@PostConstruct
	private void init() {
		
		final String SLASH = FileSystems.getDefault().getSeparator();
		final String PATH = System.getProperty("user.dir") + SLASH + "files";
		File dir = new File(PATH);
		if(!dir.exists()) {new File(PATH).mkdir();}		
		File file = new File(PATH + SLASH + "currencies.txt");
		
//		if(file.exists() & file.length() > 2) {			
			try(Scanner scanner = new Scanner(new FileReader(file))) {
				while(scanner.hasNextLine()) {
					String line = scanner.nextLine();
					line.trim();
					if(line.length() == 3) {
						Currency currency = Currency.getInstance(line.toUpperCase());
						currencies.add(currency);
					}
					else if(line.length() == 0) break;					
					else throw new UncheckedIOException(
							new IOException("Wrong data format inside currencies.txt file"));
				}
			}
			catch (IOException exc) {
				log.error(exc.getMessage(), exc);
				throw new UncheckedIOException(exc);
			}
/*		}
		else {
			Currency usd = Currency.getInstance("USD");
			currencies.add(usd);
			Currency eur = Currency.getInstance("EUR");
			currencies.add(eur);
			Currency gbp = Currency.getInstance("GBP");
			currencies.add(gbp);
			Currency rub = Currency.getInstance("RUB");
			currencies.add(rub);
		}*/
	}
	
	@ApiOperation("Returns client's private html-page")
	@PreAuthorize("hasRole('CLIENT')")
	@GetMapping("/accounts/show/{phone}")
	public String getClientPage(@PathVariable String phone, ModelMap modelMap,
			HttpServletResponse response) {

		String current = authentication().getName();
		if(!current.equals(phone)) {
			modelMap.addAttribute("message", "Security restricted information");
			log.warn("User {} tries to get protected information about {}", current, phone);
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			return "forward:/accounts/show/" + current;
		}
/*		try {
			if(!accountService.verifyAccount(phone, current)) {
				modelMap.addAttribute("message", "Security restricted information");
				log.warn("User {} tries to get protected information", current);
				return "forward:/accounts/show/" + current;
			}
		}
		catch (Exception exc) {
			log.error(exc.getMessage(), exc);
		}*/
		
		AccountResponse account = null;
		try {
//			account = accountService.getAccountDTO(current);
			account = accountService.getFullDTO(current);
		}
		catch (EntityNotFoundException exc) {
			log.error(exc.getMessage(), exc);
		}
//		List<BillResponseDTO> bills = accountService.getBills(account.getId());
		modelMap.addAttribute("account", account);
//		modelMap.addAttribute("bills", bills);
		modelMap.addAttribute("bills", account.getBills());
		modelMap.addAttribute("currencies", currencies);
		log.info("User {} has enter own private area", account.getPhone());
		return "account/private";
	}
	
/*	@PostMapping("/accounts/show")
	public String createBill(@RequestParam String currency, ModelMap modelMap) {

		String phone = authentication().getName();
		if(currency.isEmpty()) {
			modelMap.addAttribute("message", "Please choose currency type");
			return getAccount(phone, modelMap);
		}	
		accountService.addBill(phone, currency);
		return "redirect:/accounts/show/{phone}";
	}*/
	@ApiOperation("Creates a new bill in database")
	@ApiResponse(code = 201, message = "", response = BillResponse.class)
	@PreAuthorize("hasRole('CLIENT')")
	@PostMapping("/bills/add")
	@ResponseBody
	public BillResponse createBill(@RequestParam Map<String, String> params,
			HttpServletResponse response) {

		log.info("Client {} creates new {} bill", params.get("phone"), params.get("currency"));
//		if(params.get("currency").isEmpty()) return "Please choose currency type";
//		if(params.get("phone").isEmpty()) phone = authentication().getName();		
		BillResponse bill = null;
		try {
			bill = accountService.addBill(params.get("phone"), params.get("currency"));
		}
		catch (Exception exc) {
			log.error(exc.getMessage(), exc);
		}
		response.setStatus(HttpServletResponse.SC_CREATED);
		return bill;
	}
	
/*	@PreAuthorize("hasRole('CLIENT')")
	@DeleteMapping("/accounts/show/{phone}")
	public String deleteBill(@PathVariable String phone, @RequestParam int id) {
		billService.deleteBill(id);
		return "forward:/accounts/show/{phone}";
	}*/
	
	@ApiOperation("Deletes the existing bill from database")
	@PreAuthorize("hasRole('CLIENT')")
	@DeleteMapping("/bills/delete/{id}")
	@ResponseBody
	public void deleteBill(@PathVariable int id) {
		log.info("Client {} deletes bill with id {}", authentication().getName(), id);
		billService.deleteBill(id);
	}
	
	@ApiOperation("Returns specified operation's html-page")
	@PreAuthorize("hasRole('CLIENT')")
	@PostMapping("/bills/operate")
	public String operateBill(@RequestParam Map<String, String> params, ModelMap modelMap) {
		
		modelMap.addAttribute("id", params.get("id"));
		modelMap.addAttribute("action",  params.get("action"));
		modelMap.addAttribute("balance", params.get("balance"));
		
		if(params.get("action").equals("transfer")) {
			return "bill/transfer";
		}
		if(params.get("action").equals("external")) {
			return "bill/external";
		}
		return "bill/payment";
	}
	
	@ApiOperation("Checks recipient's name and surename")
	@ApiResponses(value = 
		{@ApiResponse(code = 200, message = "", response = String.class), 
		 @ApiResponse(code = 404, message = "", response = String.class)})
	@CrossOrigin(originPatterns = "*", methods = {RequestMethod.OPTIONS, RequestMethod.POST})
	@PreAuthorize("hasRole('CLIENT')")
	@GetMapping(value = "/bills/validate/{id}", produces = MediaType.TEXT_PLAIN_VALUE)
	@ResponseBody
	public String checkOwner(@PathVariable int id, HttpServletResponse response) {
		
		BillResponse bill = null;
		try {
			bill = billService.getBillDTO(id);
		}
		catch (EntityNotFoundException exc) {
			log.error(exc.getMessage(), exc);
			response.setStatus(HttpServletResponse.SC_NOT_FOUND);
			return exc.getMessage();
		}		
		return bill.getOwner().getName() + " " + bill.getOwner().getSurname();
	}
	
	@ApiOperation("Operates money by specified action's type")
	@PreAuthorize("hasRole('CLIENT')")
	@PatchMapping("/bills/launch/{id}")
	public String operateMoney(@PathVariable int id, @RequestParam(required=false) String recipient,
			@RequestParam Map<String, String> params, ModelMap modelMap, 
			RedirectAttributes redirectAttributes, HttpServletResponse response) {
		
		String phone = authentication().getName();
		int target = -1;
		if(recipient != null) {
			target = Integer.parseInt(recipient);
			if(params.get("action").equals("transfer")) {
				try {
					billService.getBillDTO(target);
				}
				catch (EntityNotFoundException exc) {
					log.error(exc.getMessage(), exc);
					modelMap.addAttribute("id", id);
					modelMap.addAttribute("action", params.get("action"));
					modelMap.addAttribute("balance", params.get("balance"));
					modelMap.addAttribute("message", exc.getMessage());
					response.setStatus(HttpServletResponse.SC_NOT_FOUND);
					return "bill/transfer";
				}
			}
		}		
		log.info("User {} performs {} operation with bill {}", phone, params.get("action"), id);
		
		final String currency = billService.getBillDTO(id).getCurrency();
		final Action action = Action.valueOf(params.get("action").toUpperCase());
		Operation operation;
		switch(action) {		
		case DEPOSIT:
//			try {
				operation = operationService.deposit
				(Double.valueOf(params.get("amount")), params.get("action"), currency, id, "Demo");
				billService.deposit(operation);
				log.info("{} has been added to bill {}", params.get("amount"), id);
//			}
//			catch (PaymentException exc) {
/*				log.warn(exc.getMessage(), exc);
				modelMap.addAttribute("id", id);
				modelMap.addAttribute("action", params.get("action"));
				modelMap.addAttribute("balance", params.get("balance"));
				modelMap.addAttribute("message", exc.getMessage());
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return "bill/payment";*/
//			}
			break;
			
		case WITHDRAW:
//			try {
				operation = operationService.withdraw
				(Double.valueOf(params.get("amount")), params.get("action"), currency, id, "Demo");
				billService.withdraw(operation);
				log.info("{} has been taken from bill {}", params.get("amount"), id);
//			}
//			catch (PaymentException exc) {
/*				log.warn(exc.getMessage(), exc);
				modelMap.addAttribute("id", id);
				modelMap.addAttribute("action", params.get("action"));
				modelMap.addAttribute("balance", params.get("balance"));
				modelMap.addAttribute("message", exc.getMessage());
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return "bill/payment";*/
//			}
			break;
			
		case TRANSFER:						
//			try {
				operation = operationService.transfer
				(Double.valueOf(params.get("amount")), params.get("action"), currency, id, target, 
						"Demo");
				billService.transfer(operation);
				log.info("{} has been sent from {} to bill ", params.get("amount"), id, target);

				executorService.execute(() -> {
					activateEmitter(operation.getRecipient(), operation.getAmount());
				});
//			}
//			catch (PaymentException exc) {
/*				log.warn(exc.getMessage(), exc);
				modelMap.addAttribute("id", id);
				modelMap.addAttribute("action", params.get("action"));
				modelMap.addAttribute("balance", params.get("balance"));
				modelMap.addAttribute("message", exc.getMessage());
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return "bill/transfer";*/
//			}
			break;
			
		case EXTERNAL:
			OperationRequest request = new OperationRequest(id, target, currency, 
					Double.valueOf(params.get("amount")), params.get("bank"));
			String json = null;
			try {
				json = mapper.writeValueAsString(request);
			}
			catch (JsonProcessingException exc) {
				log.warn(exc.getMessage(), exc);
			}
			
			try {
//				RestTemplate restTemplate = new RestTemplate();
				ResponseEntity<String> result = restTemplate.postForEntity(externalURL+"/verify", 
						json, String.class);
				
				if(result.getStatusCodeValue() == 200) {
//					try {
						operation = operationService.transfer
						(Double.valueOf(params.get("amount")), params.get("action"), currency, id, 
								target, params.get("bank"));
						billService.outward(operation);
						log.info("{} has been sent to bill {} in bank {}", params.get("amount"), 
								target, params.get("bank"));
						redirectAttributes.addFlashAttribute("message", result.getBody());
//					}
//					catch (PaymentException exc) {
/*						log.warn(exc.getMessage(), exc);
						modelMap.addAttribute("id", id);
						modelMap.addAttribute("action", params.get("action"));
						modelMap.addAttribute("balance", params.get("balance"));
						modelMap.addAttribute("message", exc.getMessage());
						response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
						return "bill/external";*/
//					}
				}
				else {
					log.warn(result.getBody());
					modelMap.addAttribute("id", id);
					modelMap.addAttribute("action", params.get("action"));
					modelMap.addAttribute("balance", params.get("balance"));
					modelMap.addAttribute("message", result.getBody());
					response.setStatus(result.getStatusCodeValue());
					return "bill/external";
				}
			}
/*			catch(HttpClientErrorException | HttpServerErrorException | 
					UnknownHttpStatusCodeException exc) {
				log.warn(exc.getResponseBodyAsString());
				modelMap.addAttribute("id", id);
				modelMap.addAttribute("action", params.get("action"));
				modelMap.addAttribute("balance", params.get("balance"));
				modelMap.addAttribute("message", exc.getResponseBodyAsString());
				response.setStatus(exc.getRawStatusCode());
				return "bill/external";
			}*/
			catch(ResourceAccessException exc) {
				log.error(exc.getMessage());
				modelMap.addAttribute("id", id);
				modelMap.addAttribute("action", params.get("action"));
				modelMap.addAttribute("balance", params.get("balance"));
				modelMap.addAttribute("message", "Service is temporary unavailable");
				response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
				return "bill/external";
			}
			break;
		}
		return "redirect:/accounts/show/" + phone;
	}
	
	@ApiOperation(value = "Recieves incoming payment from external systems")
	@ApiResponses(value = 
		{@ApiResponse(code = 200, message = "Successfully received", response = String.class), 
		 @ApiResponse(code = 404, message = "", responseContainer = "List", response = String.class),
		 @ApiResponse(code = 500, message = "", response = String.class)})
	@CrossOrigin(originPatterns = "${external.payment-service}", methods = {RequestMethod.OPTIONS, RequestMethod.POST})
	@PostMapping(path = "/bills/external",
					consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE},
					produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE})
	@ResponseBody
	public ResponseEntity<String> receiveMoney(@Valid @RequestBody OperationRequest dto) {	
		
/*		ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
		Validator validator = factory.getValidator();
		Set<ConstraintViolation<OperationRequest>> violations = validator.validate(dto);		
		if(!violations.isEmpty()) {
			List<String> messages = new ArrayList<>();
			for (ConstraintViolation<OperationRequest> violation : violations) {
				messages.add(violation.getMessage());
			}			
			return new ResponseEntity<List<String>>(messages, HttpStatus.BAD_REQUEST);
		}*/
		
		try {
			Operation operation = operationService.transfer
			(dto.getAmount(), Action.EXTERNAL.name().toLowerCase(), dto.getCurrency(), 
					dto.getSender(), dto.getRecipient(), dto.getBank());
			billService.external(operation);
			log.info("{} has been recieved to bill {}", operation.getAmount(), operation.getRecipient());
		}
		catch (Exception exc) {
			log.warn(exc.getMessage(), exc);
			return new ResponseEntity<String>(exc.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		}
		
		executorService.execute(() -> {
			activateEmitter(dto.getRecipient(), dto.getAmount());
		});
		
//		return new ResponseEntity<String>("Successfully recieved", HttpStatus.OK);
		return ResponseEntity.ok().body(new String("Successfully received"));
	}
	
	@ApiIgnore
	@PreAuthorize("hasRole('CLIENT')")
	@GetMapping(path = "/bills/notify")
//	@GetMapping(path = "/bills/notify", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
//	@ResponseBody
	public SseEmitter registerEmitter(HttpServletResponse response) {
		
		String phone = authentication().getName();
		SseEmitter emitter;
//		HttpStatus status;
		if(emitters.containsKey(phone)) {
			emitter = emitters.get(phone);
//			response.setStatus(HttpServletResponse.SC_OK);
//			status = HttpStatus.OK;
		}
		else {
			emitter = new SseEmitter(0L);
			emitters.putIfAbsent(phone, emitter);				
//			response.setStatus(HttpServletResponse.SC_CREATED);
//			status = HttpStatus.CREATED;
		}		
		emitter.onCompletion(()-> emitters.remove(phone, emitter));
		emitter.onTimeout(()-> emitters.remove(phone, emitter));
		emitter.onError((e)-> emitters.remove(phone, emitter));
//		response.setContentType(MediaType.TEXT_EVENT_STREAM_VALUE);
//		response.setStatus(HttpServletResponse.SC_OK);
		return emitter;
	}
	private void activateEmitter(int id, double amount) {

		BillResponse bill = billService.getBillDTO(id);
		String phone = bill.getOwner().getPhone();
		
		if(emitters.containsKey(phone)) {
			SseEmitter emitter = emitters.get(phone);
			try {
				String load = mapper.writeValueAsString(new EmitterPayload(id, amount));
				emitter.send(load);
//				emitter.send(load, MediaType.TEXT_EVENT_STREAM);
//				emitter.complete();
			}
			catch (Exception exc) {
				log.warn(exc.getMessage(), exc);
				emitter.completeWithError(exc);
			}
		}
	}
	
	@ApiOperation("Returns password's change html-page")
	@PreAuthorize("hasRole('CLIENT') or hasRole('ADMIN')")
	@GetMapping("/accounts/password/{phone}")
	public String getPasswordForm(@PathVariable String phone, Model model) {
		model.addAttribute("password", new PasswordRequest());
		return "account/password";
	}
	
	@ApiOperation("Confirms password's change web-form")
	@PreAuthorize("hasRole('CLIENT') or hasRole('ADMIN')")
	@PatchMapping("/accounts/password/{phone}")
	public String submitPassword(@PathVariable String phone,
			@ModelAttribute("password") @Valid PasswordRequest passwordRequest,
			BindingResult result, Model model, HttpServletResponse response) {

		if(result.hasErrors()) {
			log.warn(result.getFieldErrors().toString());
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			return "account/password";
		}
		
		try {
			if(!accountService.comparePassword(passwordRequest.getOldPassword(), phone)) {
				log.warn("User {} fails to confirm old password", authentication().getName());
				model.addAttribute("message", "Old password mismatch");
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				return "account/password";
			}
		}
		catch (Exception exc) {
			log.error(exc.getMessage(), exc);
		}
		
		try {
			accountService.changePassword(phone, passwordRequest.getNewPassword());
		}
		catch (Exception exc) {
			log.error(exc.getMessage(), exc);
		}
/*		if(authentication().getAuthorities().stream()
				.anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
			return "redirect:/accounts/search";
		}
		return "redirect:/accounts/show/{phone}";*/
		model.addAttribute("success", "Password changed");
		log.info("User {} changes password to a new one", authentication().getName());
		return "account/password";
	}

	@Override
	String setServiceImpl(String impl) {
		// TODO Auto-generated method stub
		return null;
	}
	
/*	@GetMapping("/operations/list")
	public String getOperations(@RequestParam int id, Model model) {
		model.addAttribute("billId", id);
		return "/account/history";
	}
	
	@GetMapping("/operations/list/{id}")
	@ResponseBody
	public Page<OperationResponseDTO> get1page(@PathVariable int id, Pageable pageable) {
		return operationService.getPage(id, pageable);
	}*/
	
}
