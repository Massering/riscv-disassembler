# printf patterns
PATTERN_LABEL = "\n%08x \t<%s>:"
PATTERN_3_ARGS = "   %05x:\t%08x\t%7s\t%s, %s, %s"
PATTERN_2_ARGS = "   %05x:\t%08x\t%7s\t%s, %s, %s"
PATTERN_LOAD_STORE_JALR = "   %05x:\t%08x\t%7s\t%s, %d(%s)"
PATTERN_J_LABEL = "   %05x:\t%08x\t%7s\t%s, 0x%x <%s>"
PATTERN_LUI_AUIPC = "   %05x:\t%08x\t%7s\t%s, 0x%x"
PATTERN_B_LABEL = "   %05x:\t%08x\t%7s\t%s, %s, 0x%x, <%s>"
PATTERN_FENCE = "   %05x:\t%08x\t%7s\t%s, %s"
PATTERN_NO_ARGS = "   %05x:\t%08x\t%7s"
PATTERN_UNKNOWN = "   %05x:\t%08x\t%-7s"

INVALID_INSTRUCTION = ("invalid_instruction",)

PATTERN_TABLE_HEADER = "\nSymbol Value              Size Type     Bind     Vis       Index Name"
PATTERN_TABLE_LINE = "[%4i] 0x%-15X %5d %-8s %-8s %-8s %6s %s"

OPCODES = {  # ={ - это я.
    '0110111': 'LUI',  #
    '0010111': 'AUIPC',  #
    '1101111': 'JAL',  #
    '1100111': 'JALR',  #
    '1100011': 'BRANCH',  #
    '0000011': 'LOAD',  #
    '0100011': 'STORE',  #
    '0010011': 'OP-IMM',  #
    '0110011': 'OP',  #
    '0001111': 'MISC-MEM',  #
    '1110011': 'SYSTEM'  #
}

REGISTERS = {
    '00000': 'zero',
    '00001': 'ra',
    '00010': 'sp',
    '00011': 'gp',
    '00100': 'tp',
    '00101': 't0',
    '00110': 't1',
    '00111': 't2',

    '01000': 's0',
    '01001': 's1',
    '01010': 'a0',
    '01011': 'a1',
    '01100': 'a2',
    '01101': 'a3',
    '01110': 'a4',
    '01111': 'a5',

    '10000': 'a6',
    '10001': 'a7',
    '10010': 's2',
    '10011': 's3',
    '10100': 's4',
    '10101': 's5',
    '10110': 's6',
    '10111': 's7',

    '11000': 's8',
    '11001': 's9',
    '11010': 's10',
    '11011': 's11',
    '11100': 't3',
    '11101': 't4',
    '11110': 't5',
    '11111': 't6',
}
