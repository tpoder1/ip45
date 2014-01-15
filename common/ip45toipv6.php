<?php
function ip45toipv6($ip45) 
{
    $bytes = explode(".", $ip45);
    if (count($bytes) > 16) {
        //print "Not valid IP45 address\n";
        return;
    }
    $IPv6 = array_fill(0,16, 0);
    for ($i = 16 - count($bytes), $j = 0; $i < 16; $i++, $j++) {
        if (!(intval($bytes[$j] >=0 && intval($bytes[$j]) <= 255))) {
            //print "Not valid IP45 address\n";
            return;
        }
        $IPv6[$i] = $bytes[$j];
    }
    return inet_ntop(inet_pton(vsprintf('%02.x%02.x:%02.x%02.x:%02.x%02.x:%02.x%02.x:%02.x%02.x:%02.x%02.x:%02.x%02.x:%02.x%02.x',$IPv6)));  
}

function ipv6toip45($ipv6) 
{

	$bin = @inet_pton($ipv6);

	if (!$bin) {
		return ;
	}

	$arr = unpack("C*", $bin);

	/* remove leading zeros */
	for ($i = 1; $i <= 11; $i++) { 
		if ($arr[$i] != 0) {
			break; 
		}
		unset($arr[$i]); 
	}

	/* convert to string */
	return implode(".", $arr);
}

/*
Examples of use: 
print ip45toipv6("147.249.10.20.170");
print ipv6toip45("::93:f90a:14aa");
print ipv6toip45("::f90a:14aa");
*/

?>
