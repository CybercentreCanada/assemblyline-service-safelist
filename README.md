# Safelisting service

This service allow you to mark as safe a set of files so they do not get scan by Assemblyline anymore. The content of the safelist is driven by safelist sources or user marked files strait from Assemblyline's UI.

## Format of Safelist data

### SQL DB

If providing a SQL DB file, we expect the format to be similar to NSRL's (namely there is FILE and PKG tables) where the updater can load and query those tables to convert the output to CSV.

### CSV

If providing a CSV file, we're expecting the format to be:

```
SHA-256,SHA-1,MD5,Filename,Filesize
<sha256>,<sha1>,<md5>,<filename>,<filesize>
...
```

Note that we're expecting a header as the first line of the CSV file.

## Trusted Distributors
Because we can't necessarily trust all the hashes that come from NSRL, we've elected to use the distributor
as a means of defining what files are deemed safe. To simplify this, you can use regex to set what distributors to trust.

For example, if I want to trust anything from 2K, I would set in the service manifest:
```yaml
config:
  ...
  trusted_distributors:
    - ^2K.* # This will capture 2K, 2K Australia, etc.
```

For a complete list of manufacturers, you can run `SELECT name FROM MFG` on each RDSv3 table from NSRL.
