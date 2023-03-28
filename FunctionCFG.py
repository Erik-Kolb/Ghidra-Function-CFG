

from ghidra.program.model.block import SimpleBlockIterator
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockReferenceIterator
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference
import os.path

#Establish the initial Block
bbModel = BasicBlockModel(currentProgram)
for func in currentProgram.getListing().getFunctions(True):  #Iterates through all functions in the program
	f_name = func.getName().strip("LAB_")
	f_name = f_name.strip("FUN_")
	f_name = f_name.lstrip('00')
	path = "C:\\Users\erik_\\OneDrive\\CFG_Files\\" + str(f_name) + ".dot"

	dot = open(path, "w+")
        out_f = "digraph " + '"' + f_name + '"' + " {"
        dot.write(out_f + "\n")

	#Creates the Blocks that can be iterated over
	codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), monitor)
	bb = codeBlockIterator.next()
	#Iterates and writes to a file all of the destinations of the block
	while codeBlockIterator.hasNext():
		successors = bb.getDestinations(monitor)
		while successors.hasNext():
			sucBBRef = successors.next()
			sucBBRefAddr = sucBBRef.getReferent()
			bb_name = str(bb).split(" ")
			bb_name = bb_name[0]
			bb_name = bb_name.strip("LAB_")
			bb_name = bb_name.strip("FUN_")
			print('"' + bb_name + '"' + " -> " + '"' + str(sucBBRefAddr) + '"')
			dot.write('"' + bb_name + '"' + " -> " + '"' + str(sucBBRefAddr) + '"' + ";\n")
		bb = codeBlockIterator.next()
	dot.write("}\n")
	dot.close()
	
	
	
	
	
	
#Better Version
from ghidra.program.model.block import SimpleBlockIterator
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockReferenceIterator
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference
import os.path

#Establish the initial Block
bbModel = BasicBlockModel(currentProgram)
for func in currentProgram.getListing().getFunctions(True):  #Iterates through all functions in the program
	f_name = func.getName().strip("LAB_")
	f_name = f_name.strip("FUN_")
	f_name = f_name.lstrip('00')
	path = "C:\\Users\erik_\\OneDrive\\CFG_Files\\" + str(f_name) + ".dot"

	dot = open(path, "w+")
        out_f = "digraph " + '"' + f_name + '"' + " {"
        dot.write(out_f + "\n")

	#Creates the Blocks that can be iterated over
	codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), monitor)
	bb = codeBlockIterator.next()
	#Iterates and writes to a file all of the destinations of the block
	while codeBlockIterator.hasNext():
		successors = bb.getDestinations(monitor)
		while successors.hasNext():
			sucBBRef = successors.next()
			bb_name = str(bb).split(" ")
			bb_name = bb_name[0]
			bb_name = bb_name.strip("LAB_")
			bb_name = bb_name.strip("FUN_")
			print('"' + bb_name + '"' + " -> " + '"' + str(sucBBRef) + '"')
			#dot.write('"' + bb_name + '"' + " -> " + '"' + str(sucBBRefAddr) + '"' + ";\n")
		bb = codeBlockIterator.next()
	dot.write("}\n")
	dot.close()
