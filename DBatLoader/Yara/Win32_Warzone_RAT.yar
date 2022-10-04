import "pe"

rule Win32_Warzone_RAT
{
	meta:
		description = "Detects unpacked Warzone RAT (a.k.a. Ave Maria) samples"
		author = "Netskope Threat Labs"
		reference = "e89c137a4faa31d639492b045a78dd115468f9191143c302d165aefe85b3c06a"

	strings:
		$str00 = "warzone" nocase
		$str01 = "Ave_Maria" nocase wide

		$pw00 = "POP3 Password" wide
		$pw01 = "SMTP Password" wide
		$pw02 = "HTTP Password" wide
		$pw03 = "IMAP Password" wide

		$browser00 = "\\Google\\Chrome\\" wide
		$browser01 = "\\Epic Privacy Browser\\" wide
		$browser02 = "\\Microsoft\\Edge\\" wide
		$browser03 = "\\UCBrowser\\" wide
		$browser04 = "\\Tencent\\QQBrowser\\" wide
		$browser05 = "\\Opera Software\\" wide
		$browser06 = "\\Blisk\\User Data\\" wide
		$browser07 = "\\Chromium\\" wide
		$browser08 = "\\BraveSoftware\\" wide
		$browser09 = "\\Vivaldi\\" wide
		$browser10 = "\\Comodo\\Dragon\\" wide
		$browser11 = "\\Torch\\" wide
		$browser12 = "\\Slimjet\\" wide
		$browser13 = "\\CentBrowser\\" wide

		$kl00 = "[ENTER]" wide
		$kl01 = "[BKSP]" wide
		$kl02 = "[TAB]" wide
		$kl03 = "[CTRL]" wide
		$kl04 = "[ALT]" wide
		$kl05 = "[CAPS]" wide
		$kl06 = "[ESC]" wide
		$kl07 = "[INSERT]" wide
		$kl08 = "[DEL]" wide

	condition:
		uint16(0) == 0x5a4d
		and (pe.number_of_resources > 0 or all of ($pw*))
		and all of ($str*)
		and 1 of ($browser*)
		and 5 of ($kl*)
}