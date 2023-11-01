package com.github.irybov.bankdemossr.service;

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
import org.springframework.transaction.annotation.Transactional;

import com.github.irybov.bankdemossr.controller.dto.OperationResponse;
import com.github.irybov.bankdemossr.entity.Operation;
import com.github.irybov.bankdemossr.repository.OperationRepository;
import com.github.irybov.bankdemossr.util.OperationSpecifications;

@Service
@Transactional(readOnly = true, noRollbackFor = Exception.class)
public class OperationServiceJPA implements OperationService {

	@Autowired
	private ModelMapper modelMapper;
	
	@Autowired
	private OperationRepository operationRepository;
	
	public OperationResponse getOne(long id) {
		return modelMapper.map(operationRepository.getById(id), OperationResponse.class);
	}
	public List<OperationResponse> getAll(int id) {

		return operationRepository.findBySenderOrRecipientOrderByIdDesc(id, id)
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
		
		return operationRepository.findAll(Specification.where(OperationSpecifications.hasAction(action)
				.and(OperationSpecifications.hasOwner(id)).and(OperationSpecifications.amountBetween(minval, maxval))
				.and(OperationSpecifications.dateBetween(mindate, maxdate))), pageable)
				.map(source -> modelMapper.map(source, OperationResponse.class));
	}
	
}
