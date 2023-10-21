

lastURL="";
function ajax(url)
{
	  var xhttp;
	  var url1="http://localhost:8000/?readData="+url;
	  //var url1="http://127.0.0.1:8000/"+url;
  xhttp=new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
		//alert(xhttp.responseText);
		if (xhttp.responseText=="is suspicious")
			alert("this page is suspicious");
		else if (xhttp.responseText=="is not safe")
			alert("this page is not safe");
    }
	 
  };
  if(url1 !=lastURL)
  {
  xhttp.open("GET", url1, true);
  xhttp.send();
  lastURL=url1;
  }
}



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
