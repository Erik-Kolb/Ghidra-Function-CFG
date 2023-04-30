import json
import os
import networkx as nx
from networkx.drawing.nx_agraph import write_dot
import argparse
from tqdm import tqdm
import logging

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)

# use argpase to take command line inputs
# command line inputs are the directory that contains dot files for each
# function

base = "/home/ek/Desktop/Ghidra-Function-CFG/results/"
res = os.path.join(base, 'greencat1')

with open(base + "/greencat1/imports.json", 'r') as of:
    imports = json.load(of)

imports_list = [v for k,v in imports.items()]

def write_rebuilt_dot(G, d):
    name = d.split('/')[-1].split('.dot')[0]
    directory = res + '/rebuilt_dot/'
    if not os.path.exists(directory):
        os.makedirs(directory)
    path = directory + name + '.dot'
    write_dot(G, path)

def dot_to_nx_graph(dot_file):

    with open(dot_file, 'r') as dot:
        data = dot.read().splitlines()

        # process dot files into networkx graph
        G = nx.DiGraph()
        func_name = data[0].split('"')[1]

        entry_node = None
        exit_node = None

        found_imports = []
        for line in data[1:]:
            if '->' in line:
                nodes = line.split('->')
                s = nodes[0].strip('"')
                e = nodes[1].strip('"').strip(';').strip('"')

                if e in imports.keys():

                    e = imports[e]
                    found_imports.append(e)
                    G.add_node(e, color='red')
                else:
                    G.add_node(e)

                G.add_node(s)                
                G.add_edge(s, e)

            elif '=' in line:
                entry_node = line.split('entry: ')[-1].split(',')[0]
                exit_node = line.split('exit: ')[-1].rstrip('"')
        

        # add edges from API calls back into the function
        adjacency_matrix = {}
        for a in G.adjacency():
            adjacency_matrix[a[0]] = a[1]
     
        for edge in G.edges():
            s = edge[0]
            e = edge[1]
            if e in found_imports:
                vals = list(adjacency_matrix[s].keys())
                vals.remove(e)
                for val in vals:
                    G.add_edge(e, val)

    write_rebuilt_dot(G, dot_file)
    return G, entry_node, exit_node


# invoke networkx to identify paths from an entry point to exit point
def generate_function_paths(G, entry, ext):

    logging.info("Generating all paths from {} to {}".format(entry, ext))
    paths = []
    for path in nx.all_simple_paths(G, entry, ext):
        paths.append(path)
    return paths

def imports_only(paths):
    logging.info("Stripping non-imports from paths")
    npaths = []
    for p in paths:
        # dump all basic blocks that are not calls to imports
        np = [x for x in p if x in imports_list]

        # avoid duplicates
        if np and np not in npaths:
            npaths.append(np)

    # return list of lists sorted by length
    return sorted(npaths, key=len)

# print lists with carriage return
def ppp(paths):
    i = 1
    for p in paths:
        logging.info("{}: {}".format(i, p))
        i += 1
#This is the dictionary that takes a line number as input and gives the capability based on the paths of the fuction
capability_sequences = {1: "Get Drive Info", 2: "Start Shell", 3:"Start Service", 4:"whoami", 5:"Create Copy of Running Process", 6: "Create Copy of Running Process", 7:"File by URL", 8:"Current Directory", 9:"Chagne Directory", 10:"Connect to C&C", 11: "Disconnect from C&C", 12:"Sart Hidden Service", 13:"Push/Pull from C&C", 14:"Drive Info"}

#Checks sequences of a function for capability
def capabilities(api_sequence, model_file, capability_dict):
    count = 0
    with open(model_file) as models:
        for model in models:
            count += 1
            model = model.strip("\n")
            model = model.split(", ")
            model_len = len(model)
            sequence_len = len(api_sequence)
            if model_len > sequence_len:
                for i in range(model_len - sequence_len +1):
                    if model[i:i+sequence_len] == api_sequence:
                        capability = capability_dict[count]
                        print(capability)

def main():

    files = [os.path.join(res, x) for x in os.listdir(res) if '.dot' in x]
    
    for dot_file in files:

        #if '402645' not in dot_file:
        #    continue
        G, en, ex = dot_to_nx_graph(dot_file)

        if not G.nodes:
            logging.debug("Empty dot file: {}\n".format(dot_file.split('/')[-1].split('.dot')[0]))
            continue

        logging.info("Analyzing {}".format(dot_file.split('/')[-1].split('.dot')[0]))
        paths = generate_function_paths(G, en, ex)
        new_paths = imports_only(paths)
        for path in new_paths:
            print(capabilities(path, "capability_models.txt", capability_sequences))

        #ppp(new_paths)

        #import IPython; IPython.embed()
  

if __name__ == "__main__":
    main()
