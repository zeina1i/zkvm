package riscv

// Instruction formats in RV32I.
// Every format shares the same 7-bit opcode in bits [6:0].

type RType struct {
	Opcode uint32
	Rd     uint32
	Funct3 uint32
	Rs1    uint32
	Rs2    uint32
	Funct7 uint32
}

type IType struct {
	Opcode uint32
	Rd     uint32
	Funct3 uint32
	Rs1    uint32
	Imm    int32 // sign-extended 12-bit immediate
}

type SType struct {
	Opcode uint32
	Funct3 uint32
	Rs1    uint32
	Rs2    uint32
	Imm    int32 // sign-extended 12-bit immediate
}

type BType struct {
	Opcode uint32
	Funct3 uint32
	Rs1    uint32
	Rs2    uint32
	Imm    int32 // sign-extended 13-bit immediate (multiples of 2)
}

type UType struct {
	Opcode uint32
	Rd     uint32
	Imm    int32 // upper 20 bits, already shifted left by 12
}

type JType struct {
	Opcode uint32
	Rd     uint32
	Imm    int32 // sign-extended 21-bit immediate (multiples of 2)
}

// signExtend sign-extends a value of `bits` width to int32.
func signExtend(val uint32, bits uint) int32 {
	shift := 32 - bits
	return int32(val<<shift) >> shift
}

// decodeR extracts fields from an R-type instruction.
//
// Encoding: funct7[31:25] rs2[24:20] rs1[19:15] funct3[14:12] rd[11:7] opcode[6:0]
func decodeR(instr uint32) RType {
	return RType{
		Opcode: instr & 0x7F,
		Rd:     (instr >> 7) & 0x1F,
		Funct3: (instr >> 12) & 0x7,
		Rs1:    (instr >> 15) & 0x1F,
		Rs2:    (instr >> 20) & 0x1F,
		Funct7: (instr >> 25) & 0x7F,
	}
}

// decodeI extracts fields from an I-type instruction.
func decodeI(instr uint32) IType {
	return IType{
		Opcode: instr & 0x7F,
		Rd:     (instr >> 7) & 0x1F,
		Funct3: (instr >> 12) & 0x7,
		Rs1:    (instr >> 15) & 0x1F,
		Imm:    signExtend(instr>>20, 12),
	}
}

// decodeS extracts fields from an S-type instruction.
func decodeS(instr uint32) SType {
	imm := ((instr>>25)&0x7F)<<5 | ((instr >> 7) & 0x1F)
	return SType{
		Opcode: instr & 0x7F,
		Imm:    signExtend(imm, 12),
		Funct3: (instr >> 12) & 0x7,
		Rs1:    (instr >> 15) & 0x1F,
		Rs2:    (instr >> 20) & 0x1F,
	}
}

// decodeB extracts fields from a B-type instruction.
func decodeB(instr uint32) BType {
	return BType{
		Opcode: instr & 0x7F,
		Funct3: (instr >> 12) & 0x7,
		Rs1:    (instr >> 15) & 0x1F,
		Rs2:    (instr >> 20) & 0x1F,
		Imm:    signExtend(instr>>20, 12),
	}
}

// decodeU extracts fields from a U-type instruction.
func decodeU(instr uint32) UType {
	return UType{
		Opcode: instr & 0x7F,
		Rd:     (instr >> 7) & 0x1F,
		Imm:    int32(instr & 0xFFFFF000),
	}
}

// decodeJ extracts fields from a J-type instruction.
func decodeJ(instr uint32) JType {
	imm := ((instr >> 31) << 20) |
		(((instr >> 12) & 0xFF) << 12) |
		(((instr >> 20) & 0x1) << 11) |
		(((instr >> 21) & 0x3FF) << 1)
	return JType{
		Opcode: instr & 0x7F,
		Rd:     (instr >> 7) & 0x1F,
		Imm:    signExtend(imm, 21),
	}
}
