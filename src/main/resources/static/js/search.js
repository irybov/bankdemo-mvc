$(document).ready(function(){
    
    const token = $("meta[name='_csrf']").attr("content");
    const header = $("meta[name='_csrf_header']").attr("content");
    const requestHeaders = {};
    requestHeaders[header] = token;
	
    $('#search_form').submit(function (ev) {
        ev.preventDefault();
		$('#client_table tbody').empty();
		$('#bills_table tbody').empty();
 		$.getJSON('/bankdemo/accounts/search/'+$('#phone').val(),
 			function(data){
	 		var account = '<tr>'
				+ '<td class=align-middle align=center>'+data.id+'</td>'
				+ '<td class=align-middle align=center>'+data.name+'</td>'
				+ '<td class=align-middle align=center>'+data.surname+'</td>'
				+ '<td class=align-middle align=center>'+data.phone+'</td>'
				+ '<td></td>'
			    + '<td class=align-middle align=center>'+data.birthday+'</td>'
			    + '<td class=align-middle align=center id="target_bool">'+data.active+'</td>'
				+ '<td><button class="btn btn-danger" id="target_status">Switch<br/>status'
				+ '</button></td></tr>';
		 	$(account).appendTo('#client_table tbody');
		 	
			$('#target_status').click(function(){
				if(!confirm('Are you sure to switch the status?')){
                    return false;
   				}
     			$.ajax({
    				type: 'PATCH',
    				url: '/bankdemo/accounts/status/'+data.id,
    				headers: requestHeaders,
     	        	success: function(bool) {
     	        		$('#target_bool').html(bool);
     	        	}
    			});
			});

	    	let totalPages = 1;
 			$.each(data.bills, function(key, value){
 				var rowID = value.id;
	 			var info = '<tr id="row'+rowID+'">'
					+ '<td class=align-middle align=center>'+value.id+'</td>'
					+ '<td class=align-middle align=center>'+value.balance+'</td>'
					+ '<td class=align-middle align=center>'+value.currency+'</td>'
					+ '<td class=align-middle align=center id="bill_bool'+rowID+'">'+value.active+'</td>'
					+ '<td class=align-middle align=center>'
 					+ '<button class="btn btn-danger" id="bill_status'+rowID+'">Switch<br/>status'
 					+ '</button>'
 					+ '<button class="btn btn-info" id="show_events'+rowID+'">Show<br/>events'
 					+ '</button>'
 					+ '<button class="btn btn-success" id="export_csv'+rowID+'">Export<br/>to CSV'
 					+ '</button></td></tr>';
				$(info).appendTo('#bills_table tbody');
				
				var statusBTN = '#bill_status'+rowID;
	 			$(statusBTN).click(function(){
    				if(!confirm('Are you sure to switch the status?')){
                        return false;
       				}
 					var switcher = '#bill_bool'+rowID;
 	     			$.ajax({
	 					type: 'PATCH',
	 					url: '/bankdemo/bills/status/'+rowID,
	 					headers: requestHeaders,
	 	 	        	success: function(bool) {
	 	 	        		$(switcher).html(bool);
	 	 	        	}
 	     			});
	 			});
	 			
	 			var eventsBTN = '#show_events'+rowID;
	 	    	$(eventsBTN).click(function(){
	 	    		var billId = rowID;
	 	    		var newWindow = window.open
	 	    		('/bankdemo/operations/list/', '_blank');
//	 	    		location.reload();
	 	    		$(newWindow.document.body).append
	 	    		('<script th:inline="javascript">var rowID = '+billId+';</script>');
	 	    	});
	 			
/*	 			var eventsBTN = '#show_events'+rowID;
	 	    	$(eventsBTN).click(function(){
	 	 			$('#info_table tbody').empty();
//	 		 		$.getJSON('http://localhost:8080/bankdemo/operations/list/'+rowID,
	 	 		    $.ajax({
	 	 		        type: 'GET',
	 	 		        url: 'http://localhost:8080/bankdemo/operations/list/'+rowID,
	 	 		        data: {
	 	 		            "page": 0,
	 	 		            "size": 5
	 	 		        },
		 		 		success: function(response){
//		 		 	 		$('#info_table tbody').empty();	 	 		        	
		 		 			var information = '';
		 		 			$.each(response.content, function(key, value){
		 						information += '<tr>';
		 						information += '<td align=center>'+value.id+'</td>';
		 						information += '<td align=center>'+value.action+'</td>';
		 						information += '<td></td>';
		 						information += '<td align=center>'+value.amount+'</td>';
		 						information += '<td align=center>'+value.currency+'</td>';
		 						information += '<td align=center>'+value.sender+'</td>';
		 						information += '<td align=center>'+value.recipient+'</td>';
		 						information += '<td></td>';
		 						information += '<td align=center>'+value.createdAt+'</td>';
		 						information += '</tr>';
		 		 			});
		 		 			$('#info_table tbody').append(information);
		 		 			
//		 			        if($('ul.pagination li').length - 2 != response.totalPages){
		 			        // build pagination list at the first time loading
			 			        $('ul.pagination').empty();
			 			        buildPagination(response, rowID);
//	 			        	}	
		 	 		    }
	 			    });	 	 		    
	 	 			$('#info_table tbody').hide().fadeIn('slow');
	 		    });*/

	 	    	var exportBTN = '#export_csv'+rowID;
	 			$(exportBTN).click(function(){
 	     			$.ajax({
	 					type: 'GET',
	 					url: '/bankdemo/operations/print/'+rowID,
	 	                success: function (data) {
	 	                    //Convert the Byte Data to BLOB object.
	 	                    var blob = new Blob([data], { type: "application/octetstream" });
	 	                    var fileName = 'Bill-'+rowID+'.csv';
	 	                    //Check the Browser type and download the File.
	 	                    var isIE = false || !!document.documentMode;
	 	                    if (isIE) {
	 	                        window.navigator.msSaveBlob(blob, fileName);
	 	                    }
	 	                    else {
	 	                        var url = window.URL || window.webkitURL;
	 	                        link = url.createObjectURL(blob);
	 	                        var a = $("<a />");
	 	                        a.attr("download", fileName);
	 	                        a.attr("href", link);
	 	                        $("body").append(a);
	 	                        a[0].click();
	 	                        $("body").remove(a);
	 	                    }
	 	                }
	 				});
	 			});		 			
 			});
 			
 			function fetchNotes(startPage, billID) {
 	 			$('#info_table tbody').empty();
// 		 		$.getJSON('http://localhost:8080/bankdemo/operations/list/'+rowID,
 	 		    $.ajax({
 	 		        type: 'GET',
 	 		        url: '/bankdemo/operations/list/'+billID,
 	 		        data: {
 	 		            "page": startPage,
 	 		            "size": 5
 	 		        },
	 		 		success: function(response){
//	 		 	 		$('#info_table tbody').empty();	 	 		        	
	 		 			var information = '';
	 		 			$.each(response.content, function(key, value){
	 						information += '<tr>';
	 						information += '<td align=center>'+value.id+'</td>';
	 						information += '<td align=center>'+value.action+'</td>';
	 						information += '<td></td>';
	 						information += '<td align=center>'+value.amount+'</td>';
	 						information += '<td align=center>'+value.currency+'</td>';
	 						information += '<td align=center>'+value.sender+'</td>';
	 						information += '<td align=center>'+value.recipient+'</td>';
	 						information += '<td></td>';
	 						information += '<td align=center>'+value.createdAt+'</td>';
	 						information += '</tr>';
	 		 			});
	 		 			$('#info_table tbody').append(information);
	 		 			
	 		 			$('ul.pagination').empty();
	 		 			buildPagination(response, billID);
	 	 		    }
 			    });	 	 		    
 	 			$('#info_table tbody').hide().fadeIn('slow');
 			} 			
 			
 		    function buildPagination(response, billID) {
 		    	totalPages = response.totalPages;
 		    	var pageNumber = response.pageable.pageNumber;
 		    	var numLinks = 5;
 		    	
 		    	// print 'previous' link only if not on page one
 		    	var first = '';
 		    	var prev = '';
 		    	if (pageNumber > 0) {
 		    		if(pageNumber !== 0) {
 		    			first = '<li class="page-item"><a class="page-link" id="'+billID+'">« First</a></li>';
 		    		}
 		    		prev = '<li class="page-item"><a class="page-link" id="'+billID+'">‹ Prev</a></li>';
 		    	} else {
 		    		prev = ''; // on the page one, don't show 'previous' link
 		    		first = ''; // nor 'first page' link
 		    	}
 		    	
 		    	// print 'next' link only if not on the last page
 		    	var next = '';
 		    	var last = '';
 		    	if (pageNumber < totalPages) {
 		    		if(pageNumber !== totalPages - 1) {
 		    			next = '<li class="page-item"><a class="page-link" id="'+billID+'">Next ›</a></li>';				
 		    			last = '<li class="page-item"><a class="page-link" id="'+billID+'">Last »</a></li>';
 		    		}
 		    	} else {
 		    		next = ''; // on the last page, don't show 'next' link
 		    		last = ''; // nor 'last page' link
 		    	}
 		    	
 		    	var start = pageNumber - (pageNumber % numLinks) + 1;
 		    	var end = start + numLinks - 1;
 		    	end = Math.min(totalPages, end);
 		    	var pagingLink = '';
 		    	
 		    	for (var i = start; i <= end; i++) {
 		    		if (i == pageNumber + 1) {
 		    			pagingLink += '<li class="page-item active"><a class="page-link" id="'+billID+'"> ' + i + ' </a></li>'; // no need to create a link to current page
 		    		} else {
 		    			pagingLink += '<li class="page-item"><a class="page-link" id="'+billID+'"> ' + i + ' </a></li>';
 		    		}
 		    	}	 	 		    	
 		    	// return the page navigation link
 		    	pagingLink = first + prev + pagingLink + next + last;	 	 		    	
 		    	$("ul.pagination").append(pagingLink);
 		    }
 		    
 		    $(document).on("click", "ul.pagination li a", function() {
 		        var data = $(this).attr('data');
 		    	let val = $(this).text();
 		    	let billID = $(this).attr('id');
//	 	 		    	console.log('val: ' + val);
 		    	// click on the NEXT tag
 		    	if(val.toUpperCase() === "« FIRST") {
 		    		let currentActive = $("li.active");
 		    		fetchNotes(0, billID);
 		    		$("li.active").removeClass("active");
 		      		// add .active to next-pagination li
 		      		currentActive.next().addClass("active");
 		    	} else if(val.toUpperCase() === "LAST »") {
 		    		fetchNotes(totalPages - 1, billID);
 		    		$("li.active").removeClass("active");
 		      		// add .active to next-pagination li
 		      		currentActive.next().addClass("active");
 		    	} else if(val.toUpperCase() === "NEXT ›") {
 		      		let activeValue = parseInt($("ul.pagination li.active").text());
 		      		if(activeValue < totalPages){
 		      			let currentActive = $("li.active");
 		    			startPage = activeValue;
 		    			fetchNotes(startPage, billID);
 		      			// remove .active class for the old li tag
 		      			$("li.active").removeClass("active");
 		      			// add .active to next-pagination li
 		      			currentActive.next().addClass("active");
 		      		}
 		      	} else if(val.toUpperCase() === "‹ PREV") {
 		      		let activeValue = parseInt($("ul.pagination li.active").text());
 		      		if(activeValue > 1) {
 		      			// get the previous page
 		    			startPage = activeValue - 2;
 		    			fetchNotes(startPage, billID);
 		      			let currentActive = $("li.active");
 		      			currentActive.removeClass("active");
 		      			// add .active to previous-pagination li
 		      			currentActive.prev().addClass("active");
 		      		}
 		      	} else {
 		    		startPage = parseInt(val - 1);
 		    		fetchNotes(startPage, billID);
 		      		// add focus to the li tag
 		      		$("li.active").removeClass("active");
 		      		$(this).parent().addClass("active");
 		    		//$(this).addClass("active");
 		      	}
 		    });
/* 		    (function(){
 		    	// get first-page at initial time
 		    	fetchNotes(0);
 		    });*/
	    })
	    .done(function() { $('#message').empty(); })
	    .fail(function() { $('#message').html("Phone number not found"); });
		$('#client_table tbody').hide().fadeIn('fast');
		$('#bills_table tbody').hide().fadeIn('slow');
    });
    
});

/*$(document).ready(function(){
	$('.account_status').click(function(){
 			$.ajax({
			type: 'GET',
			url: 'http://localhost:8080/bankdemo/accounts/status/'+$(this).val(),
        	success: function(bool) {
        		$('#account_bool').html(bool);
        	}
		});
	});
});
$(document).ready(function(){
	$('.bill_status').click(function(){
		var switcher = '#bill_bool'+$(this).val();
 			$.ajax({
			type: 'GET',
			url: 'http://localhost:8080/bankdemo/bills/status/'+$(this).val(),
        	success: function(bool) {
        		$(switcher).html(bool);
        	}
		});
	});
});
$(document).ready(function(){
	$('.export_csv').click(function(){
		$.get('http://localhost:8080/bankdemo/operations/print/'+$(this).val());
	});
});
$(document).ready(function(){
	$('.show_events').click(function(){
		$('#info_body').empty();
 		$.getJSON('http://localhost:8080/bankdemo/operations/list/'+$(this).val(),
 				function(data){
 			var information = '';
 			$.each(data, function(key, value){
				information += '<tr>';
				information += '<td align=center>'+value.id+'</td>';
				information += '<td align=center>'+value.action+'</td>';
				information += '<td align=center>'+'</td>';
				information += '<td align=center>'+value.amount+'</td>';
				information += '<td align=center>'+value.currency+'</td>';
				information += '<td align=center>'+value.sender+'</td>';
				information += '<td align=center>'+value.recipient+'</td>';
				information += '<td align=center>'+'</td>';
				information += '<td align=center>'+value.timestamp+'</td>';				
				information += '</tr>';
 			});
 			$('#info_body').append(information);
	    });
 		$('#info_body').hide().fadeIn('slow');
    });
});*/