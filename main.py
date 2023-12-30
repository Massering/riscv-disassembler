import sys

from constants import *
from util import *


def disassemble_instruction(instruction: bytes):
    p = bytes_to_strs(instruction)
    com = ''.join(p)

    if len(com) < 32:
        return INVALID_INSTRUCTION

    opcode = com[-7:]

    if opcode == '0110111':    # 'LUI':
        imm, rd = com[:-12], com[-12:-7]
        return PATTERN_LUI_AUIPC, 'lui', REGISTERS[rd], int(imm, 2)

    elif opcode == '0010111':    # 'AUIPC':
        imm, rd = com[:-12], com[-12:-7]
        return PATTERN_LUI_AUIPC, 'auipc', REGISTERS[rd], int(imm, 2)

    elif opcode == '1101111':    # 'JAL':
        imm, rd = com[:-12], com[-12:-7]
        imm = imm[0] * 12 + imm[12:20] + imm[11] + imm[:11] + '0'
        return PATTERN_J_LABEL, 'jal', REGISTERS[rd], int(imm, 2), '<>'

    elif opcode == '1100111':    # 'JALR':
        imm, rs1, func3, rd = com[:12], com[12:-15], com[-15:-12], com[-12:-7]
        return PATTERN_LOAD_STORE_JALR, 'jalr', REGISTERS[rd], int(imm, 2), REGISTERS[rs1]

    elif opcode == '1100011':    # 'BRANCH':
        _, rs2, rs1, func3, _ = com[:-25], com[-25:-20], com[-20:-15], com[-15:-12], com[-12:-7]
        ops = {
            '000': 'beq',
            '001': 'bne',
            '100': 'blt',
            '101': 'bge',
            '110': 'bltu',
            '111': 'bgeu'
        }
        imm = com[0] * 20 + com[-8] + com[1:7] + com[-12:-8] + '0'
        return PATTERN_B_LABEL, ops[func3], REGISTERS[rs1], REGISTERS[rs2], int(imm, 2), '<>'

    elif opcode == '0000011':    # 'LOAD':
        imm, rs1, func3, rd = com[:-20], com[-20:-15], com[-15:-12], com[-12:-7]
        ops = {
            '000': 'lb',
            '001': 'lh',
            '010': 'lw',
            '100': 'lbu',
            '101': 'lhu',
        }
        return PATTERN_LOAD_STORE_JALR, ops[func3], REGISTERS[rd], int(imm, 2), REGISTERS[rs1]

    elif opcode == '0100011':    # 'STORE':
        imm, rs2, rs1, func3, imm2 = com[:-25], com[-25:-20], com[-20:-15], com[-15:-12], com[-12:-7]
        ops = {
            '000': 'sb',
            '001': 'sh',
            '010': 'sw'
        }
        return PATTERN_LOAD_STORE_JALR, ops[func3], REGISTERS[rs2], int(imm2, 2), REGISTERS[rs1]

    elif opcode == '0010011':    # 'OP-IMM':
        imm, rs1, func3, rd = com[:-20], com[-20:-15], com[-15:-12], com[-12:-7]

        ops = {
            '000': 'addi',
            '010': 'slti',
            '011': 'sltiu',
            '100': 'xori',
            '110': 'ori',
            '111': 'andi',
        }
        if func3 in ops:
            return PATTERN_2_ARGS, ops[func3], REGISTERS[rd], REGISTERS[rs1], to_int(imm)
        else:
            return INVALID_INSTRUCTION

    elif opcode == '0110011':    # 'OP':
        opcode2, rs2, rs1, func3, rd = com[:7], com[7:12], com[12:-15], com[-15:-12], com[-12:-7]
        ops_map = {
            '0000000': {
                '000': 'add',
                '001': 'sll',
                '010': 'slt',
                '011': 'sltu',
                '100': 'xor',
                '101': 'srl',
                '110': 'or',
                '111': 'and',
            },
            '0100000': {
                '000': 'sub',
                '101': 'sra'
            },
            # RV32M Standard Extension
            '0000001': {
                '000': 'mul',
                '001': 'mulh',
                '010': 'mulhsu',
                '011': 'mulhu',
                '100': 'div',
                '101': 'divu',
                '110': 'rem',
                '111': 'remu',
            }
        }
        if opcode2 in ops_map:
            ops = ops_map[opcode2]
            if func3 in ops:
                return PATTERN_2_ARGS, ops[func3], REGISTERS[rd], REGISTERS[rs1], REGISTERS[rs2]
            else:
                return INVALID_INSTRUCTION
        else:
            return INVALID_INSTRUCTION

    elif opcode == '0001111':    # 'MISC-MEM':
        fm, pred, succ, rs1, func3, rd = com[:4], com[4:8], com[8:12], com[12:-15], com[-15:-12], com[-12:-7]

        if com == '1000' + '0011' + '0011' + '00000' + '000' + '00000' + '0001111':
            return PATTERN_NO_ARGS, 'fence.tso'
        elif com == '0000' + '0001' + '0000' + '00000' + '000' + '00000' + '0001111':
            return PATTERN_NO_ARGS, 'pause'
        else:
            s = 'i' * int(succ[0]) + 'o' * int(succ[1]) + 'r' * int(succ[2]) + 'w' * int(succ[3])
            p = 'i' * int(pred[0]) + 'o' * int(pred[1]) + 'r' * int(pred[2]) + 'w' * int(pred[3])
            return PATTERN_FENCE, 'fence', s, p

    elif opcode == '1110011':    # 'SYSTEM':
        opcode2, rs1, func3, rd = com[:12], com[12:-15], com[-15:-12], com[-12:-7]

        if opcode2 == '000000000000':
            return PATTERN_NO_ARGS, 'ecall'
        elif opcode2 == '000000000001':
            return PATTERN_NO_ARGS, 'ebreak'
        else:
            return INVALID_INSTRUCTION

    else:
        return INVALID_INSTRUCTION


def parse_elf_header(file_path: str) -> dict:
    with open(file_path, "rb") as file:
        e_ident = file.read(16)
        e_type = file.read(2)
        e_machine = file.read(2)
        e_version = file.read(4)
        e_entry = file.read(4)
        e_phoff = file.read(4)
        e_shoff = file.read(4)
        e_flags = file.read(4)
        e_ehsize = file.read(2)
        e_phentsize = file.read(2)
        e_phnum = file.read(2)
        e_shentsize = file.read(2)
        e_shnum = file.read(2)
        e_shstrndx = file.read(2)

        elf_info = {
            "e_ident": e_ident,
            "e_type": int.from_bytes(e_type, 'little'),
            "e_machine": int.from_bytes(e_machine, 'little'),
            "e_version": int.from_bytes(e_version, 'little'),
            "e_entry": int.from_bytes(e_entry, 'little'),
            "e_phoff": int.from_bytes(e_phoff, 'little'),
            "e_shoff": int.from_bytes(e_shoff, 'little'),
            "e_flags": int.from_bytes(e_flags, 'little'),
            "e_ehsize": int.from_bytes(e_ehsize, 'little'),
            "e_phentsize": int.from_bytes(e_phentsize, 'little'),
            "e_phnum": int.from_bytes(e_phnum, 'little'),
            "e_shentsize": int.from_bytes(e_shentsize, 'little'),
            "e_shnum": int.from_bytes(e_shnum, 'little'),
            "e_shstrndx": int.from_bytes(e_shstrndx, 'little')
        }

        return elf_info


def parse_elf_file(file_path) -> (dict, bytes, list, list):
    elf_header = parse_elf_header(file_path)

    sections = []
    for i in range(elf_header['e_shnum']):
        sections.append(parse_section_header(file_path, elf_header['e_shoff'] + elf_header['e_shentsize'] * i))

    for i in sections:
        #             SHT_STRTAB
        if i['sh_type'] == 3:
            str_table = parse_strtab_section(file_path, i)
            break
    else:
        raise LookupError('No strtab section found')

    for i in sections:
        #             SHT_SYMTAB
        if i['sh_type'] == 2:
            symbol_table = parse_symtab_section(file_path, i)
            break
    else:
        raise LookupError('No symtab section found')

    for i in sections:
        #           SHT_PROGBITS             SHF_ALLOC+SHF_EXECINSTR
        if i['sh_type'] == 1 and i['sh_flags'] == 0x2 + 0x4:
            instructions = parse_text_section(file_path, i)
            text_header = i
            break
    else:
        raise LookupError('No text section found')

    return elf_header, str_table, symbol_table, instructions, text_header


def parse_strtab_section(file_path, header: dict):
    with open(file_path, 'rb') as file:
        file.seek(header['sh_offset'])
        #                                 TODO: костыль
        return file.read()


def parse_symtab_section(file_path, header) -> [dict, ..., dict]:
    with open(file_path, "rb") as file:
        file.seek(header['sh_offset'])

        names = []
        for i in range(header['sh_size'] // header['sh_entsize']):
            info = {
                'st_name': int.from_bytes(file.read(4), 'little'),
                'st_value': int.from_bytes(file.read(4), 'little'),
                'st_size': int.from_bytes(file.read(4), 'little'),
                'st_info': int.from_bytes(file.read(1), 'little'),
                'st_other': int.from_bytes(file.read(1), 'little'),
                'st_shndx': int.from_bytes(file.read(2), 'little')
            }
            names.append(info)

        return names


def parse_text_section(file_path, header):
    # print(header)
    instructions = []
    with open(file_path, 'rb') as file:
        file.seek(header['sh_offset'])
        for i in range(header['sh_size'] // 4):
            byte_instr = file.read(4)[::-1]
            # print(i, end=' ', file=output)
            instr = disassemble_instruction(byte_instr)
            instructions.append((int.from_bytes(byte_instr, 'big'),) + instr)
            # print(instr, file=output)
            # print(file=output)
    return instructions


def write_disassembly(str_table, symbol_table, instructions, text_header, output):
    symbols = {}
    for i in symbol_table:
        symbols[i['st_value']] = read_while_not_null(str_table, i['st_name'])

    cur_address = text_header['sh_addr']
    formatted_instructions = []
    labels = []
    unnamed_label_index = 0
    for i in range(len(instructions)):
        hex_pres, pattern, *args = instructions[i]
        if pattern == INVALID_INSTRUCTION:
            formatted_instructions.append(pattern[0])

        else:
            try:
                if args[-1] == '<>':
                    label_addr = (args[-2] + cur_address) % (1 << 20)
                    if label_addr in symbols:
                        label_name = symbols[label_addr]
                    else:
                        label_name = f'L{unnamed_label_index}'
                        unnamed_label_index += 1
                    labels.append((label_addr, label_name))
                    args[-1] = label_name
                    args[-2] = label_addr
                formatted_instructions.append(pattern % (cur_address, hex_pres, *args))
                cur_address += 4

            except Exception as err:
                # print(err, pattern, args, file=output)
                formatted_instructions.append(INVALID_INSTRUCTION)

    labels.sort(reverse=True)
    cur_address: int = text_header['sh_addr']
    for i in formatted_instructions:
        if labels and labels[-1][0] == cur_address:
            print(PATTERN_LABEL % labels.pop(), file=output)
        print(i, file=output)
        cur_address += 4


def parse_section_header(file_path, offset):
    with open(file_path, 'rb') as file:
        file.seek(offset)
        sh_name = file.read(4)
        sh_type = file.read(4)
        sh_flags = file.read(4)
        sh_addr = file.read(4)
        sh_offset = file.read(4)
        sh_size = file.read(4)
        sh_link = file.read(4)
        sh_info = file.read(4)
        sh_addralign = file.read(4)
        sh_entsize = file.read(4)

        section_info = {
            "header_offset": offset,
            "sh_name": int.from_bytes(sh_name, 'little'),
            "sh_type": int.from_bytes(sh_type, 'little'),
            "sh_flags": int.from_bytes(sh_flags, 'little'),
            "sh_addr": int.from_bytes(sh_addr, 'little'),
            "sh_offset": int.from_bytes(sh_offset, 'little'),
            "sh_size": int.from_bytes(sh_size, 'little'),
            "sh_link": int.from_bytes(sh_link, 'little'),
            "sh_info": int.from_bytes(sh_info, 'little'),
            "sh_addralign": int.from_bytes(sh_addralign, 'little'),
            "sh_entsize": int.from_bytes(sh_entsize, 'little')
        }

        return section_info


def read_while_not_null(b, offset):
    s = b''
    while b[offset:offset + 1] != b'\x00':
        s += b[offset:offset + 1]
        offset += 1
    return s.decode()


def write_symtab(str_table, symbol_table, output):
    print(PATTERN_TABLE_HEADER, file=output)
    for i in range(len(symbol_table)):
        line = symbol_table[i]

        if line['st_shndx'] > 100:
            ind = 'ABS'
        else:
            ind = line['st_shndx'] or 'UNDEF'

        line_type = {
            0: "NOTYPE",
            1: "OBJECT",
            2: "FUNC",
            3: "SECTION",
            4: "FILE",
            5: "COMMON",
            6: "TLS",
            10: "LOOS",
            12: "HIOS",
            13: "LOPROC",
            15: "HIPROC"
        }[(line['st_info'] & 0xf)]

        vis = {
            0: "DEFAULT",
            1: "INTERNAL",
            2: "HIDDEN",
            3: "PROTECTED"
        }[line['st_other']]

        bind = {
            0:  "LOCAL",
            1:  "GLOBAL",
            2:  "WEAK",
            10: "LOOS",
            12: "HIOS",
            13: "LOPROC",
            15: "HIPROC"
        }[(line['st_info'] >> 4)]

        print(PATTERN_TABLE_LINE % (i, line['st_value'], line['st_size'], line_type, bind, vis, ind,
                                    read_while_not_null(str_table, line['st_name'])), file=output)


if __name__ == '__main__':
    # input_file, output_file = sys.argv[1:]
    # input_file, output_file = r'test_data/test_elf', r'test_data/ref_disasm.txt'
    input_file, output_file = r'test_data/test.elf', r'test_data/test.disasm.txt'
    # input_file, output_file = r'test_data/test2.elf', r'test_data/test2.disasm.txt'
    output = open(output_file, 'w')

    elf_header, str_table, symbol_table, instructions, text_header = parse_elf_file(input_file)
    print('.text', file=output)
    write_disassembly(str_table, symbol_table, instructions, text_header, output)
    print('\n\n.symtab', file=output)
    write_symtab(str_table, symbol_table, output)
