var port = null;
var callbackFunction =null;

function onDisconnected() { 
  port = null;
}
  
function disconnect(){
  port.disconnect();
}

function sendNativeMessage(message) {
  port.postMessage(message);
}

function onNativeMessage(message) {
  if(!message.ERROR) {
    if(!message.ENCRYPTION){
      console.log("Message received from the host application: "+message.VALUE+" and Signature: "+message.SIGNATURE);
    }
    else
    {
      console.log("Message received from the host application: "+message.ENCRYPTION+" and Signature: "+message.SIGNATURE);
    }
  callbackFunction({"data":message});
    console.log("Success message sent to the webpage");

  }
  else{
    console.log("Error message received from the host application: "+message.ERROR);
  callbackFunction({"success" :false});
    console.log("NO Success message sent to the webpage");

  }
  disconnect();
}

function connect() {
  var hostName = "com.asier.testsecurejs";
  port = chrome.runtime.connectNative(hostName);
  port.onMessage.addListener(onNativeMessage);
  port.onDisconnect.addListener(onDisconnected);
}

chrome.runtime.onMessageExternal.addListener(
  function(request, sender, sendResponse) {
          console.log("Request received from the webpage");
  if (request.secret)
  {
      console.log("Everything OK");
      chrome.browserAction.setBadgeText({text: "OK"});
             connect();
      if (port){
        sendNativeMessage(request.secret);
        console.log("Message sent to host application");
      }
      else{
        console.log("Port closed, message not sent to host");
      }
  }
  callbackFunction=sendResponse;
  console.log("True sent to the webpage");
  return true;
});
console.log("Ready in the background");

