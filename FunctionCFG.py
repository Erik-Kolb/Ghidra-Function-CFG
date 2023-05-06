import json
import os
import networkx as nx
from networkx.drawing.nx_agraph import write_dot
import argparse
from tqdm import tqdm
# import logging

# logging.basicConfig()
# logging.getLogger().setLevel(#logging.DEBUG)

# use argpase to take command line inputs
# command line inputs are the directory that contains dot files for each
# function


def write_rebuilt_dot(G, d, file):
    name = d.split('/')[-1].split('.dot')[0]
    directory = file + '/rebuilt_dot/'
    if not os.path.exists(directory):
        os.makedirs(directory)
    path = directory + name + '.dot'
    write_dot(G, path)


def dot_to_nx_graph(dot_file, file):

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

    write_rebuilt_dot(G, dot_file, file)
    return G, entry_node, exit_node


# invoke networkx to identify paths from an entry point to exit point
def generate_function_paths(G, entry, ext):

    paths = []
    for path in nx.all_simple_paths(G, entry, ext):
        paths.append(path)
    return paths


def imports_only(paths, imports_list):
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
        # logging.info("{}: {}".format(i, p))
        i += 1
# This is the dictionary that takes a line number as input and gives the
# capability based on the paths of the fuction

# Checks sequences of a function for capability

def extract_API_sequence(api_sequence, capability_models):

    with open(capability_models) as models:
        for model in models:
            model = model.strip("\n")
            model = model.split(" - ")
            capability = model[1]
            model = model[0]
            model_list = model.split(", ")
            model_len = len(model_list)

            sequence_len = len(api_sequence)
            if model_len <=  sequence_len:
                for i in range(model_len - sequence_len + 1):
                    if model_list[i:i + sequence_len] == api_sequence:
                        return capability, str(api_sequence)


def capability_analysis(results, imports_list, capability_models):

    files = [os.path.join(results, x)
             for x in os.listdir(results) if '.dot' in x]

    malware_name = results.split('/')[-1]
    print("[+] Analyzing the {} malware.".format(malware_name))
    capability_path = results.strip(
        malware_name) + malware_name + "_capabilities.json"
    capability_results = {malware_name: {}}
    for dot_file in files:
        G, en, ex = dot_to_nx_graph(dot_file, results)

        if not G.nodes:
            # logging.debug("Empty dot file: {}\n".format(dot_file.split('/')[-1].split('.dot')[0]))
            continue
        function_name = str(dot_file.split('/')[-1].split('.dot')[0])
        if function_name == "401406" or function_name == "lpStartAddress_00402292" or function_name == "401e12" or function_name == "401ba9" or function_name == "402292":
            continue
        # logging.info("Analyzing {}".format(dot_file.split('/')[-1].split('.dot')[0]))
        paths = generate_function_paths(G, en, ex)
        new_paths = imports_only(paths, imports_list)
        capability_list = {}
        for path in new_paths:
            x = extract_API_sequence(path, capability_models)
            if x:
                new_capability = x[0]
                api_sequence = x[1]
     
                if new_capability and str(new_capability) not in capability_list.keys():
                    capability_list[new_capability] = api_sequence

        if capability_list:
            
            capability_results[malware_name][function_name] = capability_list
            print("[+] Matched capability in function: " + function_name)
            print(u" \u2558" + " Capability ")
            for c in capability_list:
                print(u"   \u257E" + " {}".format(c))

    with open(capability_path, 'w') as capability_output:
        json.dump(capability_results, capability_output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="What is the name of the directory?")
    parser.add_argument(
        "dir_path",
        metavar="DIR",
        type=str,
        help="The Directory containing the malware to be analyzed")
    parser.add_argument(
        "file",
        metavar="FILE",
        type=str,
        help="The File containing the capability models")
    args = parser.parse_args()

    capabilty_models = args.file

    malware_results_folder = args.dir_path
    malware_results = [
        malware_results_folder +
        x for x in os.listdir(malware_results_folder) if '.json' not in x]

    for mal in malware_results:

        with open(mal + "/imports.json", 'r') as of:
            imports = json.load(of)
        imports_list = [v for k, v in imports.items()]

        capability_analysis(mal, imports_list, capabilty_models)
        print("[+] Analysis complete!\n")

