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
