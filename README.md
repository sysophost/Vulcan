# Vulcan
Tool to extract various things from `.nessus` files.
At the moment it does common service URIs (`--services`), SMB shares (`--shares`), and SMB share permissions (`--sharepermissions`).

Services can optionally be filtered to just http[s] using `--urls`.

In all cases, FQDNs can be included, where present, by specifying `--fqdns`

Verbose output is written to `stderr`, so useful output can be piped directly to file, other tools, or the clipboard.

## Usage
`python vulcan.py --inputfile <input .nessus file> [--urls] [--fqdns]` 

### Required args
`--inputfile` / `-if`

Path to the input `.nessus` file to parse
<br><br><br>
**You will need to specify at least one of `--services`, `--shares`, or `--sharepermissions`**

### Optional args
`--services` / `-sv`

Extract all services identified by the `Service Detection` plugin in *unauthenticated* scans

`--urls` / `-u`

Only extract http[s] URIs from the extracted services

`--shares` / `-sh`

Extract SMB shares identified by the `Microsoft Windows SMB Shares Enumeration` in *authenticated* scans

`--sharepermissions` / `-sp`

Extract SMB share permissions identified by the `Microsoft Windows SMB Share Permissions Enumeration` in *authenticated* scans

`--fqdns` / `-f`

Output FQDN instead of IP address (where one exists)

## Examples
### Extract all http[s] endpoints and open in firefox
`python vulcan.py --inputfile <input .nessus file> --services --urls [--fqdns]  | xargs firefox`

*This assumes that `firefox` is on the path*

## TODO
* Work out what to do with services that are not identified by Nessus
* Handle hosts with multple FQDNs
* Design a better data structure to hold a mapping between Nessus service names and the associated URI
* Take screenshots of http[s] URIs