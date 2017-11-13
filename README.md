# Examen de ASI331

Chiffrer un fichier :
```bash
python run.py -e -p PASSWORD -I SALT -i INPUT.txt -o CRYPTED.enc
```

Déchiffrer un fichier :
```bash
python run.py -d -p PASSWORD -I SALT -i CRYPTED.enc -o OUTPUT.txt
```

Aucune compilation n'est nécéssaire.
