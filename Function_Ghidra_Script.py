#TODO write a description for this script
#@author
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here


from ghidra.program.model.block import SimpleBlockIterator
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockReferenceIterator
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference
import os.path
import json

malware = currentProgram.getName()
dump = "/home/ek/Desktop/Ghidra-Function-CFG/results/" + malware
if not os.path.exists(dump):
	os.makedirs(dump)

# extract imported fucntions
sm = currentProgram.getSymbolTable()
symb = sm.getExternalSymbols()
imports = {}
for s in symb:
	imports[str(s.getAddress())] = str(s)

bbModel = BasicBlockModel(currentProgram)
for func in currentProgram.getListing().getFunctions(True):


	codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), monitor)
	bb = codeBlockIterator.next()
	

	f_name = func.getName().strip("LAB_")

	# add thunk functions to list of imports
	if 'FUN' not in f_name:
		location = str(bb.getDestinations(monitor).next()).split(' -> ')[0]
		imports[str(location)] = f_name

	f_name = f_name.strip("FUN_")
	f_name = f_name.lstrip("00")
	print(f_name)
        
	path = dump + "/"+ str(f_name) + ".dot"

	dot = open(path, "w+")
	out_f = "digraph" + '"' + f_name + '"' + " {"
	dot.write(out_f + "\n")

	entry_node = None
	exit_node = None

	while codeBlockIterator.hasNext():
		successors = bb.getDestinations(monitor)
		while successors.hasNext():
			bb_name = str(bb).split(" ")
			bb_name = bb_name[0]
			bb_name = bb_name.strip("LAB_")
			bb_name = bb_name.strip("FUN_")
			destination = successors.next()
			new_block_dest = str(destination).split('> ')[-1]

			if not entry_node:
				entry_node = bb_name
			exit_node = new_block_dest
				
			dot.write('"' + bb_name + '"' + "->" + '"' + new_block_dest + '"' + ";\n")
			print('"' + bb_name + '"' + "->" + '"' + new_block_dest + '"')

		bb = codeBlockIterator.next()



	if entry_node and exit_node:
		entry_out = "entry: {}, ".format(entry_node)
		exit_out = "exit: {}".format(exit_node)
		dot.write('comment = "{}{}"\n'.format(entry_out, exit_out))
	dot.write("}\n")
	dot.close()


with open(dump + "/imports.json", "w") as of:
	json.dump(imports, of)

