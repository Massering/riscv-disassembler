import random
import sys
import struct
from io import TextIOWrapper

from constants import *
from util import *


def disassemble_instruction(instruction: bytes):
    p = bytes_to_strs(instruction)
    com = ''.join(p)

    if len(com) < 32:
        return INVALID_INSTRUCTION

    # print(com)
    opcode = int(com[-7:], 2)

    OPCODES = {  # ={ - это я.
        0b0000011: 'LOAD',  #
        0b0001111: 'MISC-MEM',  #
        0b0010011: 'OP-IMM',  #
        0b0010111: 'AUIPC',  #
        0b0100011: 'STORE',  #
        0b0110011: 'OP',  #
        0b0110111: 'LUI',  #
        0b1100011: 'BRANCH',  #
        0b1100111: 'JALR',  #
        0b1101111: 'JAL',  #
        0b1110011: 'SYSTEM'  #
    }

    if opcode not in OPCODES:
        return INVALID_INSTRUCTION

    opname = OPCODES[opcode]
    if opname == 'LUI':
        imm, rd = com[:-12], com[-12:-7]
        return PATTERN_2_ARGS, 'lui', rd, imm

    elif opname == 'AUIPC':
        imm, rd = com[:-12], com[-12:-7]
        return PATTERN_2_ARGS, 'auipc', rd, imm

    elif opname == 'JAL':
        imm, rd = com[:-12], com[-12:-7]
        return PATTERN_2_ARGS, 'jal', rd, imm

    elif opname == 'JALR':
        imm, rs1, func3, rd = com[:12], com[12:-15], com[-15:-12], com[-12:-7]

        #                                                   TODO: imm(rs1)
        return PATTERN_LOAD_STORE_JALR, 'jalr', rd, imm

    elif opname == 'BRANCH':
        imm1, rs2, rs1, func3, imm2 = com[:6], com[6:12], com[12:-15], com[-15:-12], com[-12:-7]
        ops = {
            0b000: 'beq',
            0b001: 'bne',
            0b100: 'blt',
            0b101: 'bge',
            0b110: 'bltu',
            0b111: 'bgeu'
        }
        #                                                           TODO: pcrel_13
        return PATTERN_B_LABEL, ops[int(func3, 2)], rs2, rs1, imm1

    elif opname == 'LOAD':
        imm, rs1, func3, rd = com[:12], com[12:-15], com[-15:-12], com[-12:-7]
        ops = {
            0b000: 'lb',
            0b001: 'lh',
            0b010: 'lw',
            0b100: 'lbu',
            0b101: 'lhu',
        }
        #                                                            TODO: imm(rs1)
        return PATTERN_LOAD_STORE_JALR, ops[int(func3, 2)], rd, imm

    elif opname == 'STORE':
        imm, rs2, rs1, func3, imm2 = com[:6], com[6:12], com[12:-15], com[-15:-12], com[-12:-7]
        ops = {
            0b000: 'sb',
            0b001: 'sh',
            0b010: 'sw',
        }
        #                                                                TODO: imm(rs1)
        return PATTERN_LOAD_STORE_JALR, ops[int(func3, 2)], rs2, imm

    elif opname == 'OP-IMM':
        imm, rs1, func3, rd = com[:12], com[12:-15], com[-15:-12], com[-12:-7]
        opcode2, shamt = com[:7], com[7:12]
        ops_map = {
            0b0000000: {
                0b001: 'slli',
                0b101: 'srli'
            },
            0b0100000: {
                0b101: 'srai'
            }
        }
        if int(opcode2, 2) in ops_map:
            ops = ops_map[int(opcode2, 2)]
            if int(func3, 2) not in ops:
                return INVALID_INSTRUCTION
            return PATTERN_2_ARGS, ops[int(func3, 2)], rd, rs1, shamt
        else:
            ops = {
                0b000: 'addi',
                0b010: 'slti',
                0b011: 'sltiu',
                0b100: 'xori',
                0b110: 'ori',
                0b111: 'andi',
            }
            if int(func3, 2) not in ops:
                return INVALID_INSTRUCTION
            return PATTERN_2_ARGS, ops[int(func3, 2)], rd, rs1, imm

    elif opname == 'OP':
        opcode2, rs2, rs1, func3, rd = com[:7], com[7:12], com[12:-15], com[-15:-12], com[-12:-7]
        ops_map = {
            0b0000000: {
                0b000: 'add',
                0b001: 'sll',
                0b010: 'slt',
                0b011: 'sltu',
                0b100: 'xor',
                0b101: 'srl',
                0b110: 'or',
                0b111: 'and',
            },
            0b0100000: {
                0b000: 'sub',
                0b101: 'sra'
            },
            # RV32M Standard Extension
            0b0000001: {
                0b000: 'mul',
                0b001: 'mulh',
                0b010: 'mulhsu',
                0b011: 'mulhu',
                0b100: 'div',
                0b101: 'divu',
                0b110: 'rem',
                0b111: 'remu',
            }
        }
        if int(opcode2, 2) in ops_map:
            ops = ops_map[int(opcode2, 2)]
            return PATTERN_2_ARGS, ops[int(func3, 2)], rd, rs1, rs2
        else:
            return INVALID_INSTRUCTION

    elif opname == 'MISC-MEM':
        fm, pred, succ, rs1, func3, rd = com[:4], com[4:8], com[8:12], com[12:-15], com[-15:-12], com[-12:-7]

        if com == '1000' + '0011' + '0011' + '00000' + '000' + '00000' + '0001111':
            return PATTERN_NO_ARGS, 'fence.tso'
        elif com == '0000' + '0001' + '0000' + '00000' + '000' + '00000' + '0001111':
            return PATTERN_NO_ARGS, 'pause'
        else:
            return PATTERN_FENCE, 'fence', succ, pred

    elif opname == 'SYSTEM':
        opcode2, rs1, func3, rd = com[:12], com[12:-15], com[-15:-12], com[-12:-7]

        if int(opcode2, 2) == 0:
            return PATTERN_NO_ARGS, 'ecall'
        elif int(opcode2, 2) == 1:
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
            break
    else:
        raise LookupError('No text section found')

    return elf_header, str_table, symbol_table, instructions


def parse_strtab_section(file_path, header: dict):
    with open(file_path, 'rb') as file:
        file.seek(header['sh_offset'])
        #                                 TODO: костыль
        return file.read(header['sh_size'] + 100)


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
    instructions = []
    with open(file_path, 'rb') as file:
        file.seek(header['sh_offset'])
        for _ in range(header['sh_size'] // 4):
            byte_instr = file.read(4)[::-1]
            instr = disassemble_instruction(byte_instr)
            instructions.append(instr)
    return instructions


def write_disassembly(str_table, symbol_table, instructions, output):
    for i in instructions:
        # TODO
        if i == INVALID_INSTRUCTION:
            print(i, file=output)
        else:
            try:
                print(i[0] % (random.randint(0, 0xffff), random.randint(0, 0xfffff), *i[1:]), file=output)
            except:
                print(INVALID_INSTRUCTION, file=output)


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
    input_file, output_file = sys.argv[1:]
    output = open(output_file, 'w')

    elf_header, str_table, symbol_table, instructions = parse_elf_file(input_file)
    print('.text\n')
    write_disassembly(str_table, symbol_table, instructions, output)
    print('\n\n.symtab\n')
    write_symtab(str_table, symbol_table, output)
