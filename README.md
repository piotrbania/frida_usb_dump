# frida_usb_dump
Frida script that allows to sniff USB traffic on macOS.

I've used this script to dump and investigate the checkm8 / checkra1n jailbreak back in the day. It dumps the data to DUMP_FILE_PATH with some additional ascii markers for further parsing.
The OFFSETS_* were dumped on macos bigsur as far as i recall.

(PS. those markers in the dumped file like 'AAAA'etc. were just to make sure the entry was dumped correctly)

- piotr ( piotrbania.com), 2021.  
	
