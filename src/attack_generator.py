from argparse import ArgumentParser
import random


def get_formatted_data(data):
    string_data = ""

    first = True
    for hex_num in data:
        if first:
            first = False
            string_data += hex_num
        else:
            string_data += " " + hex_num

    return string_data


if __name__ == "__main__":
    parser = ArgumentParser(description=""" Synthetic CAN attack generator script. """,
                            epilog="""List of parameters:
                            --input_file : the original clean can log
                            --attack_type : define how to modify the chosen bytes
                                const: replace the value with a constant value
                                random: replace the value with random values
                                delta: add a constant to the original value
                                add_incr: add a continuously increasing value to the original value (it is reset to 0 after 
                                    the value 255) 
                                add_decr: add a continuously decreasing value to the original value (it is reset to 255 after 
                                    the value 0)
                                change_incr: replace the value to a continuously increasing value (it is reset to 0 after 
                                    the value 255)
                                change_decr: replace the value to a continuously decreasing value (it is reset to 255 after 
                                    the value 0)
                            --attacked_id : the chosen ID to attack
                            --offset : the offset of the bytes in the message to attack
                            --width : the length of the bytes in the message to attack
                            --start_time : a value between 0 and 1: the ratio when the attack should start regarding the full
                                length of the capture""")
    parser.add_argument('-if', '--input_file', type=str, required=True)
    parser.add_argument('-at', '--attack_type', type=str, choices=['const', 'random', 'delta', 'add_incr', 'add_decr',
                                                                   'change_incr', 'change_decr'], required=True)
    parser.add_argument('-ad', '--attack_data', type=int)
    parser.add_argument('-ai', '--attacked_id', type=int, required=True)
    parser.add_argument('-o', '--offset', type=int, required=True)
    parser.add_argument('-w', '--width', type=int, required=True)
    parser.add_argument('-st', '--start_time', type=float, required=True)
    args = parser.parse_args()

    if args.attack_type in ['const', 'delta'] and (
            not args.attack_data or args.attack_data < 0 or args.attack_data > 255):
        parser.error("const and delta attack types require an attack data integer between 0 and 255")

    attacked_id = "{:04x}".format(args.attacked_id)

    messages = []
    incr = 0

    with open(args.input_file) as file:
        for row in file:
            row_split = row.split(' ')
            row_split = [x.rstrip() for x in row_split if x != '']
            messages.append(row_split)

    log_duration = float(messages[-1][0]) - float(messages[0][0])
    attack_start_time = int(float(messages[0][0]) + log_duration * args.start_time)

    for message in messages:
        if incr == 255:
            incr = 0
        if message[1] == attacked_id and float(message[0]) >= attack_start_time:
            if len(message[4:]) >= args.offset + args.width:

                if args.attack_type == 'const':
                    message[4:] = ["{:02x}".format(args.attack_data)
                                   if args.offset <= index < args.offset + args.width
                                   else byte for index, byte in enumerate(message[4:])]

                if args.attack_type == 'delta':
                    message[4:] = ["{:02x}".format(int(byte, 16) + args.attack_data)
                                   if args.offset <= index < args.offset + args.width and
                                   int(byte, 16) + args.attack_data <= 255
                                   else byte for index, byte in enumerate(message[4:])]

                if args.attack_type == 'random':
                    message[4:] = ["{:02x}".format(random.randint(0, 255))
                                   if args.offset <= index < args.offset + args.width
                                   else byte for index, byte in enumerate(message[4:])]

                if args.attack_type == 'add_incr':
                    incr += 1
                    message[4:] = ["{:02x}".format(int(byte, 16) + incr)
                                   if args.offset <= index < args.offset + args.width and int(byte,16) + incr <= 255
                                   else byte for index, byte in enumerate(message[4:])]

                if args.attack_type == 'add_decr':
                    incr += 1
                    message[4:] = ["{:02x}".format(int(byte, 16) - incr)
                                   if args.offset <= index < args.offset + args.width and int(byte,16) - incr >= 0
                                   else byte for index, byte in enumerate(message[4:])]

                if args.attack_type == 'change_incr':
                    message[4:] = ["{:02x}".format(incr)
                                   if args.offset <= index < args.offset + args.width
                                   else byte for index, byte in enumerate(message[4:])]
                    incr += 1

                if args.attack_type == 'change_decr':
                    message[4:] = ["{:02x} ".format(255 - incr)
                                   if args.offset <= index < args.offset + args.width
                                   else byte for index, byte in enumerate(message[4:])]
                    incr += 1
            else:
                raise ValueError("There are no selected bytes for given attacked_id, offset and width.")

    with open(
            args.attack_type + "-" + str(args.attacked_id) + "-" + str(args.offset) + "-" + str(args.width) + "-" + str(
                args.start_time) + ".csv", 'w') as out_file:
        for message in messages:
            out_file.write(message[0] + "        ")
            out_file.write(message[1] + "    ")
            out_file.write('000    ')
            out_file.write(message[3] + "    ")
            out_file.write(get_formatted_data(message[4:]) + "\n")
