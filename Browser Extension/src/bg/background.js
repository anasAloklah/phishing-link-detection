

lastURL="";
function ajax(url)
{
	  var xhttp;
	  var url1="http://localhost:8000/?readData="+url;
	  //var url1="http://127.0.0.1:8000/"+url;
	  
	      fetch("http://localhost:8000/?readData="+url, {
      method: 'GET',
      headers: {
        
        'Content-Type': 'application/text'
      }
    }).then(res => {
		alert(res.Text);
		if (res.Text =="is suspicious")
			alert("this page is suspicious");
		else if (res.Text =="is not safe")
			alert("this page is not safe");
      //return res.Text();
    }).then(res => {
      //senderResponse(res);
    })

}

// background script



chrome.webNavigation.onCompleted.addListener(function() {
		chrome.tabs.query({
		active: true,
		currentWindow: true,
		lastFocusedWindow: true
	}, function(tabs) {
		// and use that tab to fill in out title and url
		var tab = tabs[0];
		//console.log(tab.url);
		//alert(tab.url);
		ajax(tab.url);
		setTimeout(function (){lastURL=""}, 3000);
	});
});
