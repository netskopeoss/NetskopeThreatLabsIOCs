### Script

Netskope Threat Labs is releasing a script that can be used to decode BlackSnake strings, given a decompiled source code.

You can use any .NET decompiler to obtain the BlackSnake code, like dnSpy.

The strings can be decoded by running the following command:

```shell
(venv) python3 decode_strings.py --source decompiled_code

[+] Decoded strings saved at decompiled_code_decoded.txt

```

You can also use the --print to see all decoded strings in the console.