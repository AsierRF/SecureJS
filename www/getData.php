<?php 
$data = $_POST['data'];

$fileData = fopen("/path/to/data/receivedData.txt", "a") or die("Unable to open file!");

fwrite($fileData, "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
if(isset($data['ENCRYPTION']) ){
	fwrite($fileData, "ENCRYPTION:\n\n" . $data['ENCRYPTION'] . "\n\n");
	fwrite($fileData, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fwrite($fileData, "SIGNATURE:\n\n" . $data['SIGNATURE'] . "\n\n");
}
else if(isset($data['VALUE']) ){
	fwrite($fileData, "VALUE:\n\n" . $data['VALUE'] . "\n\n");
	fwrite($fileData, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fwrite($fileData, "SIGNATURE:\n\n" . $data['SIGNATURE'] . "\n\n");
}else {
	fwrite($fileData, "ERROR:\n\n" . $data['ERROR'] . "\n\n");
}
fwrite($fileData, "-----------------------------------------------------------------\n");
fclose($fileData);

?>
