# IOCs

* **SHA256 (Stage 01)**
```text
a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92
```

* **SHA256 (Stage 02)**
```text
dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78
```

* **SHA256 (Stage 03)**
```text
9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d
```

* **SHA256 (Stage 04)**
```text
34ca75a8c190f20b8a7596afeb255f2228cb2467bd210b2637965b61ac7ea907
```

* **Payload URL**
```text
hxxps://cdn.discordapp[.]com/attachments/928503440139771947/930108637681184768/Tbopbh.jpg
```

* **Created Files**
```text
%TEMP%\InstallUtil.exe
%TEMP%\AdvancedRun.exe
%TEMP%\Nmddfrqqrbyjeygggda.vbs
```

* **Executed Commands**
```text
"%TEMP%\AdvancedRun.exe" /EXEFilename C:\Windows\System32\sc.exe /WindowState 0 /CommandLine ""stop WinDefend"" /StartDirectory """" /RunAs 8 /Run
"%TEMP%\AdvancedRun.exe" /EXEFilename C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /WindowState 0 /CommandLine ""rmdir 'C:\ProgramData\Microsoft\Windows Defender' -Recurse"" /StartDirectory """" /RunAs 8 /Run
```

* **Targeted Extensions**
```text
.3DM .3DS .602 .7Z .ACCDB .AI .ASC .ASM .ASP .BACKUP .BAT .BRD .BZ .C .CLASS .CONFIG .CSR .CSV .DBF .DCH .DER .DOCX .DOTM .DOTX .EDB .GO .GZ .HDD .HTM .HTML .IBD .INC .INI .ISO .JAVA .JPEG .JPG .JS .KDBX .KEY .MML .MSG .MYD .NEF .ODP .ONETOC2 .OTG .OTS .OTT .PAQ .PAS .PDF .PEM .PHP .PL .PNG .POT .POTM .POTX .PPAM .PPK .PPSM .PPSX .PPTM .PPTX .PST .PY .RAR .RAW .RB .SAV .SLK .SLN .SQ3 .SQLITE3 .SQLITEDB .STC .STI .STW .SVG .SXD .TAR .TBK .TIFF .UOP .VB .VBS .VDI .VMSD .VMSN .VMSS .VMTM .VMX .VSD .WKS .XHTML .XLM .XLS .XLSB .XLSM .XLTM .XLTX .XLW 
```
