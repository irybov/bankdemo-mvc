package com.github.irybov.bankdemossr.util;

import java.time.OffsetDateTime;

import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import com.github.irybov.bankdemossr.entity.Operation;
import com.github.irybov.bankdemossr.entity.Operation_;

@Component
public class OperationSpecifications {
	
	public static Specification<Operation> hasAction(String action){
			
		return(root, query, builder) -> {return builder.like(root.get
								(Operation_.ACTION), "%"+action+"%");};
	}
	
	public static Specification<Operation> hasOwner(int id){
		
		return (root, query, builder) -> {return builder.or
				(builder.equal(root.get(Operation_.SENDER), id),
				builder.equal(root.get(Operation_.RECIPIENT), id));};
	}
	
	public static Specification<Operation> amountBetween(double minval, double maxval){
		
		return(root, query, builder) -> {return builder.between(root.get
									(Operation_.AMOUNT), minval, maxval);};
	}
	
	public static Specification<Operation> dateBetween(OffsetDateTime mindate, OffsetDateTime maxdate){
		
		return(root, query, builder) -> {return builder.between(root.get
									(Operation_.CREATED_AT), mindate, maxdate);};
	}
	
}
