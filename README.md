# Vulcan
Tool to extract common URIs from `.nessus` files

## Usage
`python vulcan.py --inputfile <input .nessus file> [--urls] [--fqdns]` 

### Required args
`--inputfile` / `-if`

Path to the input `.nessus` file to parse

### Optional args
`--urls` / `-u`

Only extract http[s] URIs

`--fqdns` / `-f`

Output FQDN instead of IP address (where one exists)

### Extract all http[s] endpoints and open in firefox
`python vulcan.py -if <input .nessus file> -u  | xargs firefox`

*This assumes that `firefox` is on the path*

## TODO
* Work out what to do with services that are not identified by Nessus
* Handle hosts with multple FQDNs
* Design a better data structure to hold a mapping between Nessus service names and the associated URI
* Take screenshots of http[s] URIs