# viriius
Viriius feeds your FortiSandbox with samples from the Malshare repository. For research purposes only!

Usage:

go run viriius.go <options>

Command Line Options (from the code):

malshareAPIKey = flag.String("a", "", "Malshare API key.")
path           = flag.String("p", "viriius.db", "Path to hash cache DB (will be created if non-existent).")
storelocal     = flag.String("l", "", "Download locally: create a copy of the file in target folder. Will not submit to FSA.")
dryrun         = flag.Bool("d", false, "Dry run: display list of new hashes but dont download them.")
ignore         = flag.Bool("i", false, "Ignore existing hash list and download all new files.")
ssl            = flag.Bool("s", false, "Disable SSL certificate validation (useful when testing inline MITM inspection device).")
logexists      = flag.Bool("e", false, "Output message for files that already exist.")
submittofsa    = flag.Bool("f", false, "Submit to FSA.")
FSAIP          = flag.String("fip", "192.168.129.15", "FSA IP address.")
FSAUsername    = flag.String("fuser", "admin", "FSA Username.")
FSAPasswd      = flag.String("fpass", "password", "FSA Password.")

 
