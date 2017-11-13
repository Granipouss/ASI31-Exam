# Examen de ASI331

Encrypt a file:
```bash
python run.py -e -p PASSWORD -I SALT -i INPUT.txt -o CRYPTED.enc
```

Decrypt a file:
```bash
python run.py -d -p PASSWORD -I SALT -i CRYPTED.enc -o OUTPUT.txt
```

No compilation needed
