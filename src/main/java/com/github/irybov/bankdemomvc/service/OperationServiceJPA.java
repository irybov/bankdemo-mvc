package com.github.irybov.bankdemomvc.service;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
//import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
//import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.github.irybov.bankdemomvc.controller.dto.OperationResponse;
import com.github.irybov.bankdemomvc.entity.Operation;
import com.github.irybov.bankdemomvc.jpa.OperationJPA;
import com.github.irybov.bankdemomvc.util.OperationSpecification;

@Service
@Transactional(readOnly = true, noRollbackFor = Exception.class)
public class OperationServiceJPA implements OperationService {

	@Autowired
	private ModelMapper modelMapper;
	
	@Autowired
	private OperationJPA operationJPA;
	
	public OperationResponse getOne(long id) {
		return modelMapper.map(operationJPA.getById(id), OperationResponse.class);
	}
	public List<OperationResponse> getAll(int id) {

		return operationJPA.findBySenderOrRecipientOrderByIdDesc(id, id)
				.stream()
				.map(source -> modelMapper.map(source, OperationResponse.class))
				.collect(Collectors.toList());
	}
/*	@Transactional(readOnly = true, noRollbackFor = Exception.class)
	public Page<OperationResponseDTO> getPage(int id, OperationPage page){
		
		Pageable pageable = PageRequest.of(page.getPageNumber(), page.getPageSize(),
				Sort.by("id").descending());
		return operationRepository.findBySenderOrRecipient(id, id, pageable)
				.map(OperationResponseDTO::new);
	}*/
	public Page<OperationResponse> getPage(int id, String action, double minval, double maxval,
			OffsetDateTime mindate, OffsetDateTime maxdate, Pageable pageable){
		
//		Pageable pageable = PageRequest.of(page.getPageNumber(), page.getPageSize(),
//											page.getSortDirection(), page.getSortBy());
		
		return operationJPA.findAll(OperationSpecification.orderBy
					(OperationSpecification.hasAction(action)
				.and(OperationSpecification.hasOwner(id))
				.and(OperationSpecification.amountBetween(minval, maxval))
				.and(OperationSpecification.dateBetween(mindate, maxdate))), pageable)
					.map(source -> modelMapper.map(source, OperationResponse.class));
	}
	
	@Transactional(readOnly = false, propagation = Propagation.MANDATORY, rollbackFor = Exception.class)
	public void save(Operation operation) {operationJPA.saveAndFlush(operation);}
	
}
