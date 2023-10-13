# CAN data infector

A python script to generate infected CAN logs by modifying the original messages.

## Description

## Goal

The goal of this project is to allow researchers to create malicious can data for research purposes only, eg. for evaluation of intrusion detection mechanisms. This project is part of the [CrySyS Vehicle Security Research](https://www.crysys.hu/research/vehicle-security).

If you use this script in your research, please cite [one of our relevant paper](https://www.crysys.hu/research/vehicle-security) e.g. the following:

```
@inproceedings {
   author = {Irina Chiscop and András Gazdag and Joost Bosman and Gergely Biczók},
   title = {Detecting Message Modification Attacks on the CAN Bus with Temporal Convolutional Networks},
   booktitle = {Proceedings of the 7th International Conference on Vehicle Technology and Intelligent Transport Systems},
   year = {2021}
}
```

### Functions
The implemented attack types can change the CAN data field in 7 different ways:

1. const: the original data value is replaced by the given attack data.
2. random: the original data value is replaced by a new random value in every selected message.
3. delta: the given attack data is added to the original data value.
4. add_incr: an increasing value (per selected message) is added to the original data value.
5. add_decr: an increasing value (per selected message) is substracted from the original value.
6. change_incr: the original data value is replaced by an increasing value (per selected message)
7. change_decr: the original data value is replaced by a decreasing value (per selected message)

### Input Format
The format of the expected input data is the following:

[time] [ID] [DLC] [flags] [data]

where

* time: is the capture time of the message in a unix timestamp format
* ID: is the id of the message in a hexadecimal format
* DLC: is the length of the message
* flags: is representing the potential can flags in a message (e.g. remote frame)
* data: the data part of the can message

## Usage
Run the attack_generator.py from the src folder with the necessary arguments:

1. -if   / --input_file
2. -at   / --attack_type:  choices: const, random, delta, add_incr, add_decr, change_incr or change_decr
3. -ai   / --attacked_id:  in hexadecimal form without the '0x'prefix
4. -o    / --offset:       data offset (in bits)
5. -w    / --width:        data width (in bits)
6. -st   / --start_time:   float, given in percent
7. -et   / --end_time:     float, given in percent
8. -of   / --out_folder:   str, name of the ouput folder
9. -n    / --name:         str, name of the output trace 

## Ouput format

The output trace uses the same format az the input. An extra field is added at the end of each line to indicate whether that line is modified or not.

[time] [ID] [DLC] [flags] [data] [attack_flag]

where

* time: is the capture time of the message in a unix timestamp format
* ID: is the id of the message in a hexadecimal format
* DLC: is the length of the message
* flags: is representing the potential can flags in a message (e.g. remote frame)
* data: the data part of the can message
* attack_flag: 1 if the line is modified, 0 if it is the unmodified
    
## License
This work is shared under the GNU LGPLv3 license. (See LICENSE.txt)
