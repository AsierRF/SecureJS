<html>
    <head>
        <meta charset="UTF-8">
        <title></title>
    </head>
    <body>
        <script type="text/javascript" src="jquery-3.2.1.min.js"></script>
        <h1>This can be any web page</h1>
        <div id="here"></div>
        <script>
            function go(secretValue) {
                var editorExtensionId = "kjlehhpnbpjghglhbhikjbcjmmahedka";
                console.log("I am about to send the request to the Extension");
                chrome.runtime.sendMessage(editorExtensionId, {message: "getTheEncryptedCode", secret: secretValue},
                    function(response) {
                        if (!response.success){
                            console.log("The Extension responded: No success!");
                        }
                        else {
                            console.log("The Extension responded: Success!");
                            //Send data to server
                            var parameters = {
                                    "data" : response.data
                            };
                            $.ajax({
                                    data:  parameters,
                                    url:   'getData.php',
                                    type:  'post'
                            });
                            console.log("Data sent to the server.");
                            chrome.runtime.sendMessage(editorExtensionId, {close:true}, function (response) {});
                        }
                    });
                console.log("I sent the request to the Extension");
            } 
                
            function start (){
            	//Example for Encryption Mode: substitue ???? for the right hex values
                //var encryptionSGX = {"SIGNATURE":"0x????","ENCRYPTION":"0x????","VARIABLE":[{"ORDER":"0","TYPE":"str","VALUE":"<?php echo $_GET['max'];?>"}]};
                //Example for Signature Mode: 
                var encryptionSGX = {"MAINFUNCTION":"getPrimes","CODE":"function getPrimes(max) { var primes = []; var prime = true; var value; for(var e = 2 ;e < max; e++){value=e; for(var i = 2; i < value; i++) { if(value % i === 0) {prime=false; i=value; } } if(prime){primes.push(value); } prime=true; } return primes.toString();}","SIGNATURE":"0x????","VARIABLE":[{"ORDER":"0","TYPE":"str","VALUE":"<?php echo $_GET['max'];?>"}]};
                go(encryptionSGX);
                document.getElementById('here').innerHTML +="<span>The secret has been sent.</span>";
            }
            start();
        </script>
    </body>
</html>
