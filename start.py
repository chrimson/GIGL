import json
import numpy as np
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD

  
def assign_probability(score):
    if score == 1:
        return 0.5  # 50% chance - used in one of two attacks
    elif score == 2:
        return 0.5  # 50% chance - used in one of two attacks
    elif score == 3:
        return 1.0  # 100% chance - used in both attacks
    else:
        return 0.0  # 0% chance - not used in either attack

def create_bayesian_network(techniques):
    model = BayesianNetwork()
    
    # Group techniques by tactic
    tactics = {}
    for technique in techniques:
        model.add_node(technique['techniqueID'])
        tactic = technique['tactic']
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(technique['techniqueID'])
    
    # Add a root node for each tactic
    for tactic in tactics:
        rootname = 'Root_{}'.format(tactic)
        model.add_node(rootname)
        for technique in tactics[tactic]:
            model.add_edge(rootname, technique)
    
    
    # Add CPDs
    for technique in techniques:
        node = technique['techniqueID']
        prob = assign_probability(technique['score'])
        parents = model.get_parents(node)

        if parents:
            # This technique has parent(s)
            cpd_table = np.full((2, 2**len(parents)), prob)
            cpd_table[0] = 1 - cpd_table[1]  # Probability of False
            cpd = TabularCPD(node, 2, cpd_table, evidence=parents, evidence_card=[2]*len(parents))
            
        else:
            cpd = TabularCPD(node, 2, [[1-prob], [prob]])
            
        model.add_cpds(cpd)
    
    # Add CPDs for root nodes (tactics)
    for tactic in tactics:
        root_node = f"Root_{tactic}"
        # Assuming equal probability for tactic to be active or not
        cpd = TabularCPD(root_node, 2, [[0.5], [0.5]])
        model.add_cpds(cpd)
    
    
    return model

def export_to_net(model, filename):
    with open(filename, 'w') as f:
        # Write header
        f.write("net\n{\n}\n")
        # Write node definitions
        for node in model.nodes():
            f.write(f"node {node}\n")
            f.write("{\n")
            f.write("    states = (\"False\" \"True\");\n")
            f.write(f"    label = \"{node}\";\n")
            f.write(f"    position = ({np.random.randint(0, 1000)} {np.random.randint(0, 1000)});\n")
            f.write("}\n")
        
        # Write probability definitions
        for cpd in model.get_cpds():
            node = cpd.variable
            parents = model.get_parents(node)
            f.write(f"potential_for_attack ({node}")
            if parents:
                f.write(f" | {' '.join(parents)}")
            f.write(")\n{\n")
            f.write("    data = ")
            probs = cpd.values.flatten()
            f.write("(" + " ".join(f"{p:.6f}" for p in probs) + ")")
            f.write(";\n}\n")

def main():
    json_file = r"C:\Users\prata\Downloads\layer_by_operation.json"
    with open(json_file, 'r') as f:
        data = json.load(f)
    techniques = data['techniques']
    model = create_bayesian_network(techniques)
    
    # Check if the model is valid
    if model.check_model():
        print("The Bayesian Network model is valid.")
    else:
        print("The Bayesian Network model is not valid.")
    
    # Export to .net file
    export_to_net(model, r"C:\Users\prata\Downloads\mitre_attack_bayesian.net")
    print("Bayesian Network exported to mitre_attack_bayesian.net")
main()