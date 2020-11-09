rule TroubleGrabber_PWS
{
    meta:
        
		info = "TroubleGrabber is a malware that uses Discord webhooks to communicate stolen credentials back to the attacker"
    strings:
		$a1 = "TOKEN_STEALER_CREATOR.Properties"
		$a2 = "discordapp.com/attachments/"  nocase wide ascii
	condition:
        all of ($a*)
}

rule TroubleGrabber_Sendhookfile
{
    meta:
        
		info = "TroubleGrabber is a malware that uses Discord webhooks to communicate stolen credentials back to the attacker"
    strings:
		$a1 = "sendhookfile.Properties"  nocase wide ascii
		$a2 = "TokenStealer"  nocase wide ascii
		$a3 = "api/webhooks"  nocase wide ascii
	condition:
        all of ($a*)
} 

rule TroubleGrabber_TokenStealer
{
    meta:
        
		info = "TroubleGrabber is a malware that uses Discord webhooks to communicate stolen credentials back to the attacker"
    strings:
		$a1 = "**INJECTION STARTED!**"  nocase wide ascii
		$a2 = "systeminfo | findstr"  nocase wide ascii
		$a3 = "curl -X POST -H"  nocase wide ascii
	condition:
        all of ($a*)
}