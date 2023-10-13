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


def get_attacked_part_in_int(message_data, attack_offset, attack_width):
    # get original data in binary format and
    # separate it to start, attack and end parts according to given attack_offset and attack_width
    original_data = "".join(["{0:08b}".format(int(byte, 16)) for byte in message_data])
    start, attack, end = original_data[:attack_offset], original_data[
                                                        attack_offset:attack_offset + attack_width], original_data[attack_offset + attack_width:]
    return int(attack, 2)


def get_attacked_data(attack_type, attack_data, attack_offset, attack_width, message_data, dlc):
    # get original data in binary format and
    # separate it to start, attack and end parts according to given attack_offset and attack_width
    original_data = "".join(["{0:08b}".format(int(byte, 16)) for byte in message_data])
    start, attack, end = original_data[:attack_offset], original_data[
                                                        attack_offset:attack_offset + attack_width], original_data[
                                                                                                     attack_offset + attack_width:]
    if len(attack) == 0:
        raise ValueError("there are no selected attack bits (width = 0?)")

    original_attack_value = int(attack, 2)
    # for delta and add_incr attack types, if the resulting value is bigger than the
    # maximum value (for given attack_width), the modified value will be the maximum value
    if attack_type == 'delta' or attack_type == 'add_incr':
        attack_value = min(attack_data + original_attack_value, 2 ** attack_width - 1)
    # for add_decr attack type, if the resulting value is lesser than zero, the modified value
    # will be zero
    elif attack_type == 'add_decr':
        attack_value = max(attack_data + original_attack_value, 0)
    elif attack_type == 'random':
        attack_value = random.randint(0, 2 ** attack_width - 1)
    else:
        attack_value = attack_data

    # convert the modified value to binary format, and fill with leading zeros, until it matches
    # the length of the original value
    stuffed_attack = str("{0:b}".format(attack_value)).zfill(attack_width)

    modified_data = start + stuffed_attack + end

    # return two hexadecimal values for each 8 bit segment
    return_ = ["{:02x}".format(int(modified_data[i * 8:(i * 8) + 8], 2)) for i in range(0, int(dlc))]
    return_[-1] += "\t1"
    return return_


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
                            --offset : the offset of the bits in the message to start the attack
                            --width : the number of the bits in the message to attack
                            --start_time : a value between 0 and 1: the ratio when the attack should start regarding the full
                                length of the capture
                            --end_time : a value between 0 and 1: the ratio when the attack should end regarding the full
                                length of the capture
                            --out_folder: the folder where the attacked files will be saved
                            --name: the name of the trace, attacked file will be saved as <name>-<attack_type>-<attacked_id>-<offset>-<width>-<start_time>-<end_time>.csv""")
    parser.add_argument('-if', '--input_file', type=str, required=True)
    parser.add_argument('-at', '--attack_type', type=str, choices=['const', 'random', 'delta', 'add_incr', 'add_decr',
                                                                   'change_incr', 'change_decr'], required=True)
    parser.add_argument('-ai', '--attacked_id', type=str, required=True)
    parser.add_argument('-o', '--attack_offset', type=int, required=True)
    parser.add_argument('-w', '--attack_width', type=int, required=True)
    parser.add_argument('-st', '--start_time', type=float, required=True)
    parser.add_argument('-et', '--end_time', type=float, required=True)
    parser.add_argument('-of', '--out_folder', type=str, required=True)
    parser.add_argument('-n', '--name', type=str, required=True)
    args = parser.parse_args()

    if args.end_time <= args.start_time:
        parser.error("attack end time must be greater than start time")

    messages = []
    incr = 0

    once = True

    with open(args.input_file) as file:
        for row in file:
            if not row:
                continue  # skip empty lines
            row_split = row.split(' ')
            row_split = [x.rstrip() for x in row_split if x != '']
            messages.append(row_split)

    log_duration = float(messages[-1][0]) - float(messages[0][0])
    attack_start_time = int(float(messages[0][0]) + log_duration * args.start_time)
    attack_end_time = int(float(messages[0][0]) + log_duration * args.end_time)

    incr_value = 100

    def check_if_in_attack(message):
        return message[1] == args.attacked_id and attack_start_time <= float(message[0]) <= attack_end_time

    for message in messages:
        if incr == 2 ** args.attack_width - 1:
            incr = 0
        if check_if_in_attack(message):
            if len(message[4:]) * 8 >= args.attack_offset + args.attack_width:

                 # run this only once, when the attack starts
                if once:
                    # define data for attack with the 0.2 percentage of the original value
                    initial_data = get_attacked_part_in_int(args.attack_offset, args.attack_width, message[4:])
                    initial_data_for_delta = initial_data
                    # if initial data is 0, get the mean of the attacked messages
                    if initial_data_for_delta == 0:
                        attacked_messages = [message for message in messages if check_if_in_attack(message)]                        
                        initial_data_for_delta = int(
                                            sum(  [  get_attacked_part_in_int(message_data=message[4:], attack_offset=args.attack_offset, attack_width=args.attack_width) for message in attacked_messages])
                                                / len(attacked_messages)) * 0.2

                    # print(f"Initial data: {initial_data}")
                    once = False

                if args.attack_type == 'delta':

                   
                    # print(f"Attack data: {attack_data}")
                    message[4:] = get_attacked_data(args.attack_type, initial_data_for_delta,
                                                    args.attack_offset,
                                                    args.attack_width, message[4:], message[3])

                elif args.attack_type == 'add_incr':
                    incr += incr_value
                    message[4:] = get_attacked_data(args.attack_type, incr, args.attack_offset,
                                                    args.attack_width, message[4:], message[3])

                elif args.attack_type == 'add_decr':
                    incr += incr_value
                    message[4:] = get_attacked_data(args.attack_type, -1 * incr, args.attack_offset,
                                                    args.attack_width, message[4:], message[3])

                elif args.attack_type == 'random':
                    message[4:] = get_attacked_data(args.attack_type, None,
                                                    args.attack_offset,
                                                    args.attack_width, message[4:], message[3])

                elif args.attack_type == 'const':
                    message[4:] = get_attacked_data(args.attack_type, initial_data,
                                                    args.attack_offset,
                                                    args.attack_width, message[4:], message[3])

                elif args.attack_type == 'change_incr':
                    message[4:] = get_attacked_data(args.attack_type, incr, args.attack_offset,
                                                    args.attack_width, message[4:], message[3])
                    incr += incr_value

                elif args.attack_type == 'change_decr':
                    message[4:] = get_attacked_data(args.attack_type, 2 ** args.attack_width - 1 - incr,
                                                    args.attack_offset,
                                                    args.attack_width, message[4:], message[3])
                    incr += incr_value

                else:
                    raise ValueError("Unknown attack type.")

            else:
                raise ValueError(
                    "There are no selected bits for given attacked_id, offset and width.")
        else:
            message[-1] += "\t0" 

    with open(
            f"{args.out_folder}/{args.name}-{args.attack_type}-0x{args.attacked_id}-{args.attack_offset}-{args.attack_width}-{args.start_time}-{args.end_time}.log",
            "w") as out_file:
        for message in messages:
            out_file.write(message[0] + "        ")
            out_file.write(message[1] + "    ")
            out_file.write('000    ')
            out_file.write(message[3] + "    ")
            out_file.write(get_formatted_data(message[4:]) + "\n")