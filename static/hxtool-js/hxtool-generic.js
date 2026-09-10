function hxtool_ajax_post_request(endpoint, mydata, successCallback, contentType=false) {
	$.ajax
	({
		type: "POST",
		url: endpoint,
		dataType: 'json',
		contentType: contentType,
		processData: false,
		data: mydata,
		success: successCallback,
		error: hxtoolActionFail
	})
}

function hxtool_ajax_get_request(endpoint, myargs, successCallback) {
	$.ajax
	({
		url: endpoint,
		dataType: 'json',
		contentType: 'application/json',
		data: myargs,
		success: successCallback,
		error: hxtoolActionFail
	})
}

function hxtoolActionFail(xhr, status, error) {
	var msg = "Request failed";
	var detail = "";
	var roleHint = "";
	try {
		var body = JSON.parse(xhr['responseText']);
		var inner = (typeof body['api_response'] === 'string') ? JSON.parse(body['api_response']) : body['api_response'];
		// Pull the most specific human-readable message available
		var hxMsg = (inner && (inner['message'] || (inner['presence'] && inner['presence']['message']))) || "";
		var hxDetails = [];
		['presence', 'execution'].forEach(function(k) {
			if (inner && inner[k] && inner[k]['details']) {
				inner[k]['details'].forEach(function(d) { hxDetails.push('Code ' + d['code'] + ': ' + d['message']); });
			}
		});
		if (inner && inner['details']) {
			inner['details'].forEach(function(d) { hxDetails.push('Code ' + d['code'] + ': ' + d['message']); });
		}
		if (inner && inner['role_hint']) roleHint = inner['role_hint'];
		msg = hxMsg || ("HTTP " + xhr.status + " – " + (error || status));
		detail = hxDetails.join('<br>');
	} catch(e) {
		msg = "HTTP " + xhr.status + " – " + (error || status);
		if (xhr['responseText']) detail = "<code style='font-size:11px; word-break:break-all;'>" + $('<div>').text(xhr['responseText']).html() + "</code>";
	}
	var html = "<p style='color:#ea475b; font-weight:bold; margin-bottom:6px;'>&#9888; " + $('<div>').text(msg).html() + "</p>";
	if (detail) html += "<p style='font-size:12px; color:rgba(255,255,255,0.6); margin-top:4px;'>" + detail + "</p>";
	if (roleHint) html += "<div style='margin-top:14px; padding:10px 14px; background:rgba(255,193,7,0.12); border-left:4px solid #ffc107; border-radius:3px;'>"
		+ "<p style='margin:0 0 4px; font-size:12px; font-weight:bold; color:#ffc107; letter-spacing:0.03em;'>&#128274;&nbsp; Required HX User Permissions</p>"
		+ "<p style='margin:0; font-size:12px; color:rgba(255,255,255,0.85);'>" + $('<div>').text(roleHint).html() + "</p>"
		+ "</div>";
	$("#hxtoolMessageBody").html(html);
	$("#hxtoolMessage").show();
}


function getHistoricDate(days) {
	var historicDate = new Date();
	historicDate.setDate(historicDate.getDate() - days);
	return(historicDate.toISOString().substr(0, 10))
}

function updateChartJS(name, url) {
	var jsonData = $.ajax({
		url: url,
		dataType: 'json',
	}).done(function (myChartData) {
		name.data = myChartData;
		name.options.animation.duration = 0;
		name.update();
	});
}

var getUrlParameter = function getUrlParameter(sParam) {
    var sPageURL = window.location.search.substring(1),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : decodeURIComponent(sParameterName[1]);
        }
    }
};

function hxtoolGenerateNestedTable(myData) {
	var r = "<table class='hxtool_table_host_alert hxtool_table'>";
	r += "<tbody>";
	$.each( myData, function( index, value ) {
		r += "<tr>";
		r += "<td class='hxtool_host_info_cell'>" + index + "</td>";
		r += "<td>";
		if (isObject(value)) {
			r += hxtoolGenerateNestedTable(value);
		}
		else {
			r += value;
		}
		r += "</td>";
		r += "</tr>";
	});
	r += "</tbody>";
	r += "</table>";
	return(r);
}

function hxtoolGenerateNestedObjectView(myData) {
	var r = "";
	console.log(myData);
	$.each( myData, function( index, value ) {
		r += "<div>";
		r += index + ": ";
		if (isObject(value)) {
			hxtoolGenerateNestedObjectView(value);
		}
		else {
			r += value;
		}
		r += "</div>";
	});
}

function isObject(obj) {
	return obj === Object(obj);
}
