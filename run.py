import sys, getopt
from main import encrypt, decrypt

def parse_input (argv):
    helpString  = "Usage: python main.py [-h] [-e] [-d] -p PWD -I IV -i INPUT -o OUT\n"
    helpString += "Options:\n"
    helpString += "  -h, --help             affiche ce message d'aide puis quitte\n"
    helpString += "  -e, --enc              chiffre le fichier d'entree\n"
    helpString += "  -d, --dec              dechiffre le fichier d'entree\n"
    helpString += "  -p PWD, --pwd PWD      mot de passe\n"
    helpString += "  -I IV, --IV IV         vecteur d'initialisation\n"
    helpString += "  -i INPUT, --in INPUT   fichier d'entree a chiffrer/dechiffrer\n"
    helpString += "  -o OUT, --out OUT      fichier de sortie a chiffre/dechiffre\n"
    paramList = {
        '-p': 'pwd', '-I': 'IV', '-i': 'input', '-o': 'out',
        '--pwd': 'pwd', '--IV': 'IV', '--in': 'input', '--out': 'out'
    }
    params = { 'enc': True }

    try:
        opts, args = getopt.getopt(argv, "hedp:I:i:o:", ["help", "enc", "dec", "pwd=", "IV=", "in=", "out="])
    except getopt.GetoptError:
        print helpString
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print helpString
            sys.exit()
        elif opt in ('-e', '--enc'):
            params['enc'] = True
        elif opt in ('-d', '--dec'):
            params['enc'] = False
        elif opt in paramList:
            params[paramList[opt]] = arg

    for key in paramList:
        if not paramList[key] in params:
            print "Error: %s is required" % paramList[key]
            print helpString
            sys.exit(2)

    return params

params = parse_input(sys.argv[1:])

file = open(params['input'], 'r')
m = file.read()
file.close()

if params['enc']:
    c = encrypt(params['pwd'], params['IV'], m)
    file = open(params['out'], 'w')
    file.write(c.encode('hex'))
    file.close()
else:
    d = decrypt(params['pwd'], params['IV'], m.decode('hex'))
    file = open(params['out'], 'w')
    file.write(d)
    file.close()
