## Group 3 Project
### Pratam (G)avaravarapu · Rayan (I)ssa · Harshya (G)avaravarapu · Chris (L)imson
GMU CYSE 650 Cyber Risk Modeling and Analysis Tools  
Summer 2024 · Alexandre de Barros Barreto, PhD  

Software that transforms an execution graph path from MITRE ATT&amp;CK into Bayesian representation using the UnBBayes API, incorporating the capacity to elicit and measure uncertainty in the new model representation

## Download
```
git clone https://github.com/chrimson/GIGL.git
```

## Execute
```
cd GIGL
pip install pgmpy
python3 start.py layer_by_operation.json mitre_attack_bayesian.net
```

## Documentation
For more detail,
[Tutorial.pdf](Tutorial.pdf)

## Reference
[https://chrimson.github.io/GIGL](https://chrimson.github.io/GIGL)  
[https://mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator)  
[https://github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
[https://sourceforge.net/projects/unbbayes](https://sourceforge.net/projects/unbbayes)  
[https://pgmpy.org](https://pgmpy.org)

## License
[GPL-3.0](LICENSE)
