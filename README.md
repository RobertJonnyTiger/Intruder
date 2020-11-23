# Intruder
Intruder.py - A powerful tool to customize attacks on websites. Has 4 different options of attacks

## Usage:
* usage: `intruder.py [-h] -p --payloads_sets PAYLOADS_SETS [PAYLOADS_SETS ...] [-o OUTPUT_PATH] [-s SLEEP] [-v] request_file`

* Intruder is a powerful tool for automating customized attacks against web applications. It can be used to automate all kinds
of tasks that may arise during your testing.

* **positional arguments**:
  * request_file          Request file with marked variables (POST or GET).

* **optional arguments**:
  * `-h`, `--help`           show this help message and exit
  * `-p` `--payloads_sets` PAYLOADS_SETS [PAYLOADS_SETS ...]
                        Set or multiple sets of payloads_sets to run.
  * `-o OUTPUT_PATH`, `--output OUTPUT_PATH`
                        Name for the output file. (Default: output.txt)
  * `-s SLEEP`, `--sleep SLEEP`
                        Sets a sleep timer (in secs) between requests.
  * `-v`, `--verbose`         Verbose mode to show errors

