rule Win64_CrossLock_Ransomware
{
	meta:
        description = "Detects CrossLock Ransomware"
        author = "Netskope Threat Labs"

	strings:
		$str01 = "CrossLock"
		$str02 = "The path %s will be encrypted"
		$str03 = "notepad.exe"
		$str04 = ".bak.bat.bin.blf.ckp.cmd.com.dat.dbc.dll.exe"
		$str05 = ".hta.idx.inf.key.lnk.log.msi.mwb.nls.ocx.prf"
		$str06 = ".ps1.reg.rnd.scr.sql.sys.tmd"
		$str07 = "golang.org/x/crypto/chacha20"
		$str08 = "crypto/rsa.init"

	condition:
		uint16(0) == 0x5a4d and all of them
}