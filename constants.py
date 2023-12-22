# printf patterns
PATTERN_LABEL = "\n%08x \t<%s>"
PATTERN_3_ARGS = "   %05x:\t%08x\t%7s\t%s, %s, %s"
PATTERN_2_ARGS = "   %05x:\t%08x\t%7s\t%s, %s"
PATTERN_LOAD_STORE_JALR = "   %05x:\t%08x\t%7s\t%s, %d(%s)"
PATTERN_J_LABEL = "   %05x:\t%08x\t%7s\t%s, 0x%x <%s>"
PATTERN_B_LABEL = "   %05x:\t%08x\t%7s\t%s, 0x%x, <%s>"
PATTERN_FENCE = "   %05x:\t%08x\t%7s\t%s, %s"
PATTERN_NO_ARGS = "   %05x:\t%08x\t%7s"
PATTERN_UNKNOWN = "   %05x:\t%08x\t%-7s"

INVALID_INSTRUCTION = "invalid_instruction"

PATTERN_TABLE_HEADER = "\nSymbol Value              Size Type     Bind     Vis       Index Name"
PATTERN_TABLE_LINE = "[%4i] 0x%-15X %5d %-8s %-8s %-8s %6s %s"
