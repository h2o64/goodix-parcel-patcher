# Goodix Parcel patch for Android Q

## The problem

"Parcel object increased from 104 to 120 bytes, and many functions in
both libraries had two Parcel objects next to each other in their stack.

Each of those functions had their stack modified to be increased by
32 bytes to accommodate for the increased Parcel object size. The stack
pointer offsets for the 2nd Parcel, along with any other items in the
stack after the Parcels (which was just the stack canary), were also
adjusted to accomodate for the change in Parcel size."

Source: https://github.com/jabashque/proprietary_vendor_leeco/commit/652378f8839f2851a65334a0c659d7ba06fd29cc (@jabashque)

## The solution 

This repository presents a script which automates the patching process

## Tutorial

1. Ghidra work

	a. Download Ghidra [here](https://ghidra-sre.org/)
	b. Create a new project and import all the goodix libraries (those should be in the `WORKING` folder)
	c. Analyze all the files
	d. Export as "C/C++" in `DATA/filename.c` (ex: `DATA/libfp_client.c`)
	e. Run the following command for each file
	```shell
	grep -B10 "Parcel aPStack" DATA/filename.c | grep "//" > DATA/filename_f
	```
	(/!\ This step may return lines with "Warning" in, please remove it and do this step manually)
2. `objdump`

	a. Install AARCH64 toolchain
	```shell
	sudo apt-get install binutils-aarch64-linux-gnu
	```
	b. Disassemble every file
	```shell
	aarch64-linux-android-objdump -d WORKING/filename.so > DATA/filename.asm
	```
3. Execute the script

	a. Install Python 3 depedencies
	```shell
	pip3 install -r requierments.txt
	```
	b. Replace config lines in `script.py` (the script must be executed file by file)
	```python
	asm_file = "DATA/filename.asm"
	functions_file = "DATA/filename_f"
	output_file = "WORKING/filename.so"
	```
	c. Execute the script (/!\ This will overwrite `WORKING/filename.so`)
