from ghidra.program.model.block import SimpleBlockIterator
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockReferenceIterator
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference
import os.path

bbModel = BasicBlockModel(currentProgram)
for func in currentProgram.getListing().getFunctions(True):
	f_name = func.getName().strip("LAB_")
	f_name = f_name.strip("FUN_")
	f_name = f_name.lstrip("00")
	print(f_name)

	malware = "GreenCat1"
	dump = "/home/ek/Desktop/Ghidra-Function-CFG/dot_files/malware"
	if not os.path.exists(dump):
		os.makedirs(dump)

	path = dump + "/" + str(f_name) + ".dot"

	dot = open(path, "w+")
	out_f = "digraph" + '"' + f_name + '"' + " {"
	dot.write(out_f + "\n")

	codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), monitor)
	bb = codeBlockIterator.next()
	while codeBlockIterator.hasNext():
		successors = bb.getDestinations(monitor)
		while successors.hasNext():
			bb_name = str(bb).split(" ")
			bb_name = bb_name[0]
			bb_name = bb_name.strip("LAB_")
			bb_name = bb_name.strip("FUN_")
			destination = successors.next()
			new_block_dest = str(destination).split('> ')[-1]
			print('"' + bb_name + '"' + "->" + '"' + new_block_dest + '"')
			dot.write('"' + bb_name + '"' + "->" + '"' + new_block_dest + '"' + ";\n")
		bb = codeBlockIterator.next()


	dot.write("}\n")
	dot.close()


