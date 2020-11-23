# Intruder
Intruder.py - A powerful tool to customize attacks on websites. Has 4 different options of attacks.
* **Sniper**: This uses a single set of payloads_sets. It targets each payload position in turn, and places each payload into that position in turn.
* **Battering-Ram**: Allows only 1 payload, runs on ALL the marked positions in the same time.
* **Pitchfork**: Uses multiple payload sets. There is a different payload set for each defined position (up to a
	maximum of 20). The attack iterates through all payload sets simultaneously, and places one payload
	into each defined position.
* **Cluster-Bomb**: Allows up to 20 payloads, 1 payload for each position marked. Tries all possible combinations of
    payloads per position.

## Installation:
1. Get the Burpee module from https://github.com/xscorp/Burpee and add it to your packages folder in the enviorment you are using.
2. 'git-clone https://github.com/RhoTau42/Intruder'
3. 'cd Intruder/'
4. run the program as you like with: `python3 intruder.py [OPTIONS]...`

## Usage:
1. Create a file with a POST\GET request. (Use BurpSuite and copy+paste the request to an empty file).
2. Mark the variables you want to run payloads on Example in the request: `username=var1`. Say i want to run a sniper attack on `var1`. I'll just mark the variable like so: `$var1$`.
	* You can use any kind of sign. Intruder will prompt you to specify which sign you used as a marker (By default, it's set to dollar-signs '$').
3. Run the Intruder, give it a payload(s) set(s) and specify other options if you want to. Add the required argument, `request_file`.
4. A main-menu will be prompted to ask what attack type you would like to use.
5. Make your choice and let the program run.
6. Finally, a table will be printed to stdout and saved to an output file (By dafault: `'output.txt'` - you can change that with `-o`)

**`intruder.py [-h] -p --payloads_sets PAYLOADS_SETS [PAYLOADS_SETS ...] [-o OUTPUT_PATH] [-s SLEEP] [-v] request_file`**

* Intruder is a powerful tool for automating customized attacks against web applications. It can be used to automate all kinds
of tasks that may arise during your testing.

* **positional arguments**:
  * request_file          Request file with marked variables (POST or GET).

* **optional arguments**:
  * `-h`, `--help`           show this help message and exit.
  * `-p` `--payloads_sets` PAYLOADS_SETS [PAYLOADS_SETS ...]
                        Set or multiple sets of payloads_sets to run.
  * `-o OUTPUT_PATH`, `--output OUTPUT_PATH`
                        Name for the output file. (Default: output.txt)
  * `-s SLEEP`, `--sleep SLEEP`
                        Sets a sleep timer (in secs) between requests.
  * `-v`, `--verbose`         Verbose mode to show errors.
  
  **Example**: `python3 intruder.py -p payload_set1 payload_set2 payload_set3 -o ouput.txt -s 0.75 -v`
  
  ## Requirements:
  * Burpee module: https://github.com/xscorp/Burpee
  * Python

