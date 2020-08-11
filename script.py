import struct
import re
from pwnlib.asm import disasm, asm
import pprint

asm_file = "DATA/fingerprint.goodix.default.asm"
functions_file = "DATA/fingerprint.goodix.default_f"
truth_file = None # "libfp_client5118m_new.asm"
output_file = "WORKING/fingerprint.goodix.default.so"

# Helpers for patching
def unpack_instr(s):
	d = disasm(s, arch='aarch64')
	if '#0x' in d:
		return int(re.findall(r"#0x?([0-9A-Fa-f]+)", d)[0], 16), d
	else:
		return int(re.findall(r"#[-]?(\d+)", d)[0], 10), d

def patch_command(v, d):
	t = d.split()[2]
	if t == 'add':
		return d.replace('#'+hex(v), '#'+hex(v+0x10))
	else:
		if t == 'stp':
			return d.replace('#-'+str(v), '#-'+str(v+32))
		else:
			return d.replace('#'+str(v), '#'+str(v+32))

def patch_instr(v,d):
	new_instr = patch_command(v,d)
	patch = asm(' '.join(new_instr.split()[2:]), arch='aarch64')
	return new_instr, patch


# Identify the relevant portions of code
def split_until(x):
	if len(x) == 1:
		tmp = x[0].split('(')[0]
		return (tmp, tmp)
	return (x[0], x[1].split('(')[0])

with open(functions_file, "r") as ref_file:
	names = [split_until(x[3:].split("::")) for x in ref_file.readlines()]

def is_function(line):
	return line[:5] == "00000"

functions = []
lines = []
with open(asm_file) as f:
	lines = f.readlines()
	line_num = 0
	for line in lines:
		if is_function(line):
			address, identifier = line.split()
			functions.append((line_num, int(address, 16), identifier))
		line_num += 1

relevant = []
for i in range(len(functions)):
	function = functions[i]
	for name1, name2 in names:
		if (name1 in function[2]) and (name2 in function[2]):
			begin = function[0]
			end = functions[i+1][0]
			relevant_lines = lines[begin+1:end]
			ret = []
			for line in relevant_lines:
				if ('x29' in line) and any(x in line for x in ['add','ldp','ldr','str','stp']):
					address, data = line[:-1].split()[:2]
					data_b = struct.pack('<I', int(data, 16))
					ret.append((int(address[:-1], 16), data_b))
			relevant.append(ret)
if truth_file:
	with open(truth_file) as f:
		lines_truth = f.readlines()
		truth = []
		for i in range(len(functions)):
			function = functions[i]
			for name1, name2 in names:
				if (name1 in function[2]) and (name2 in function[2]):
					begin = function[0]
					end = functions[i+1][0]
					relevant_lines = lines_truth[begin+1:end]
					ret = []
					for line in relevant_lines:
						if ('x29' in line) and any(x in line for x in ['add','ldp','ldr','str','stp']):
							address, data = line[:-1].split()[:2]
							data_b = struct.pack('<I', int(data, 16))
							ret.append((int(address[:-1], 16), data_b))
					truth.append(ret)

# Make the changes
in_blocklist = []
out_blocklist = []
with open(output_file, "r+b") as f:
	for i in range(len(relevant)):
		relevant_code = relevant[i]
		initial_pos = relevant_code[0]
		begin, initial_instr = unpack_instr(initial_pos[1])
		if 'stp' in initial_instr:
			begin = begin
			end = begin-104
		else:
			print("ERROR: No stp found")
			break
		print("Begin : " + str(begin) + " | End : " + str(end))
		new_initial_instr, initial_patch = patch_instr(begin, initial_instr)
		print("Replacing " + str(initial_pos[1]) + " with " + str(initial_patch) + " at " + str(initial_pos[0]))
		f.seek(initial_pos[0])
		f.write(initial_patch)
		for j in range(1, len(relevant_code)):
			pos = relevant_code[j]
			address, instr = unpack_instr(pos[1])
			if truth_file:
				true_address, true_instr = unpack_instr(truth[i][j][1])
			new_instr, patch = patch_instr(address, instr)
			if (pos[1] in in_blocklist) or (patch in out_blocklist):
				print('FAIL3 (Blacklist) : Replacing {} ({}) to {} ({}) at address {}'.format(pos[1], " ".join(instr.split()[2:]), patch, " ".join(new_instr.split()[2:]), str(address)))
			elif (('add' in instr) and (address+8 == end)) or (end <= address <= begin):
				if truth_file and patch != truth[i][j][1]:
					print('FAIL2 (Not in new) : Replacing {} ({}) to {} ({}) while new is {} ({}) at address {}'.format(pos[1], " ".join(instr.split()[2:]), patch, " ".join(new_instr.split()[2:]), truth[i][j][1], " ".join(new_instr.split()[2:]), str(address)))
				else:
					print('Replacing {} ({}) to {} ({}) at address {}'.format(pos[1], " ".join(instr.split()[2:]), patch, " ".join(new_instr.split()[2:]), str(address)))
					f.seek(pos[0])
					f.write(patch)
			else:
				print('FAIL1 (Not in address range) : Replacing {} ({}) to {} ({}) at address {}'.format(pos[1], " ".join(instr.split()[2:]), patch, " ".join(new_instr.split()[2:]), str(address)))
