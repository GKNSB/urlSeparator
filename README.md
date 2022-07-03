## urlSeparator
Identify non-wildcard unique URLs in Lepus findings. This is a simple helper script that assists in the identification of non-wildcard URLs. It parses either all or specific findings folders based on domain and separates the good urls from the shitty ones.

```
usage: urlSeparator.py [-h] [-d DOMAINS] lepusFindingsDir output

I find urls in Lepus directories

positional arguments:
  lepusFindingsDir      Location of Lepus findings directory
  output                Output file location

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAINS, --domains DOMAINS
                        Domain output folders to process separated by commas (Default 'all')
```