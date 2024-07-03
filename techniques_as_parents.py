import json
import numpy as np
import sys
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.global_vars import logger

risk = "Risk"

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
        tech_id = technique['name']
        model.add_node(tech_id)
        tactic = technique['tactic'].replace('-', '_').title()
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(tech_id)

    # Add techniques to each tactic
    for tactic in tactics:
        model.add_node(tactic)
        for technique in tactics[tactic]:
            model.add_edge(technique, tactic)

    # Add final result node
    model.add_node(risk)
    for tactic in tactics:
        model.add_edge(tactic, risk)

    # Add CPDs for techniques
    for technique in techniques:
        prob = assign_probability(technique['score'])
        cpd = TabularCPD(technique['name'], 2, [[1-prob], [prob]])
        model.add_cpds(cpd)
    
    # Add CPD for tactics
    for tactic in tactics:
        parents = model.get_parents(tactic)
        cpd_table = np.full((2, 2**len(parents)), prob)
        cpd_table[0] = 1 - cpd_table[1]
        cpd = TabularCPD(tactic, 2, cpd_table, evidence=parents, evidence_card=[2]*len(parents))
        model.add_cpds(cpd)

    # Add CPD for result
    parents = model.get_parents(risk)
    cpd_table = np.full((2, 2**len(parents)), prob)
    cpd_table[0] = 1 - cpd_table[1]
    cpd = TabularCPD(risk, 2, cpd_table, evidence=parents, evidence_card=[2]*len(parents))
    model.add_cpds(cpd)

    return model

def export_to_net(model, filename):
    with open(filename, 'w') as f:
        # Write header
        f.write("net\n{\n}\n")
        x = 0
        yb = 50
        offset = False

        # Write node definitions
        for node in model.nodes():
            if x > 1250:
                x = np.random.randint(0, 200)
                yb += 150
            x += 200
            if offset:
                y = yb + 50
                offset = False
            else:
                y = yb
                offset = True
            if node == risk:
                x = 800
                y = yb + 250

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

    tech_map = {}
    stix_file = 'enterprise-attack-15.1.json'
    with open(stix_file, 'r') as f:
        stix = json.load(f)
    for object in stix['objects']:
        if object['type'] == 'attack-pattern':
            for xref in object['external_references']:
                if xref['source_name'] == 'mitre-attack':
                    tech_map[xref['external_id']] = object['name'].replace(' ', '_').replace('-', '_')

    techniques = data['techniques']
    for technique in techniques:
        technique['name'] = tech_map[technique['techniqueID']]
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
