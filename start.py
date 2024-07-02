import json
import numpy as np
import sys
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.global_vars import logger

TECH_MAP = {}

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
        tech_id = technique['techniqueID']
        if tech_id in TECH_MAP:
            tech_id = TECH_MAP[tech_id].replace(' ', '_').replace('-', '_')
        model.add_node(tech_id)
        tactic = technique['tactic'].replace('-', '_').title()
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(tech_id)

    # Add a root node for each tactic
    for tactic in tactics:
        model.add_node(tactic)
        for technique in tactics[tactic]:
            model.add_edge(tactic, technique)

    # Add CPDs
    for technique in techniques:
        node = technique['techniqueID']
        if node in TECH_MAP:
            node = TECH_MAP[node].replace(' ', '_').replace('-', '_')
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
        root_node = tactic
        # Assuming equal probability for tactic to be active or not
        cpd = TabularCPD(root_node, 2, [[0.5], [0.5]])
        model.add_cpds(cpd)

    return model

def export_to_net(model, filename):
    with open(filename, 'w') as f:
        # Write header
        f.write("net\n{\n}\n")
        x = 0
        y = 0
        # Write node definitions
        for node in model.nodes():
            if node in TECH_MAP:
                node = TECH_MAP[node].replace(' ', '_').replace('-', '_')
            if x > 1000:
                x = 0
                y += 150
            x += 10*len(node)
            f.write(f"node {node}\n")
            f.write("{\n")
            f.write("    states = (\"False\" \"True\");\n")
            f.write(f"    label = \"{node}\";\n")
            f.write(f"    position = ({x} {y});\n")
            f.write("}\n")
        
        # Write probability definitions
        for cpd in model.get_cpds():
            node = cpd.variable
            parents = model.get_parents(node)
            f.write(f"potential ({node}")
            if parents:
                f.write(f" | {' '.join(parents)}")
            f.write(")\n{\n")
            f.write("    data = ")
            probs = cpd.values.flatten()
            f.write("(" + " ".join(f"{p:.6f}" for p in probs) + ")")
            f.write(";\n}\n")

def main():
    logger.disabled = True
    json_file = sys.argv[1]
    with open(json_file, 'r') as f:
        data = json.load(f)

    stix_file = 'enterprise-attack-15.1.json'
    with open(stix_file, 'r') as f:
        stix = json.load(f)
    for object in stix['objects']:
        if object['type'] == 'attack-pattern':
            for xref in object['external_references']:
                if xref['source_name'] == 'mitre-attack':
                    TECH_MAP[xref['external_id']] = object['name']

    techniques = data['techniques']
    model = create_bayesian_network(techniques)
    
    # Check if the model is valid
    if model.check_model():
        print("Bayesian Network model is valid")
    else:
        print("Bayesian Network model is not valid")
    
    # Export to .net file
    export_to_net(model, sys.argv[2])
    print("Bayesian Network exported")

main()
