package x86emu

import (
	"errors"
	"fmt"
)

const (
	opUnvisited uint8 = iota
	opFallback
	opNop
	opMovR32R32
	opMovR32M
	opMovMR32
	opMovR8R8
	opMovR8M
	opMovMR8
	opMovZX8R32
	opMovZX16R32
	opMovSX8R32
	opMovR32Imm
	opMovR8Imm
	opMovMImm32
	opMovMImm8
	opLea32
	opAlu32RR
	opAlu32RM
	opAlu32MR
	opAlu32RImm
	opAlu32MImm
	opAlu8RR
	opAlu8RM
	opAlu8MR
	opAlu8RImm
	opAlu8MImm
	opIncR32
	opDecR32
	opTest32RR
	opTest32RM
	opTest32Imm
	opTest8
	opShift32Imm
	opShift32CL
	opShift8Imm
	opShift8CL
	opPushR32
	opPopR32
	opPushImm32
	opJcc
	opJmpRel
	opCallRel
	opRet
	opSetCC
	opBswap
)

const (
	icFlagIsReg uint8 = 1 << 0
	icFlagSegFS uint8 = 1 << 1
)

// decInsn 为无指针 16 字节预解码指令缓存条目（零 GC 扫描开销）
type decInsn struct {
	kind   uint8
	length uint8
	reg    uint8
	rm     uint8
	index  uint8
	scale  uint8
	sub    uint8
	flags  uint8
	disp   uint32
	imm    uint32
}

// InitICache 为 PE .text 代码区建立惰性预解码缓存，并监听自修改写入自动失效
func (c *CPU) InitICache(start, end uint32) {
	if end <= start || end-start > 4<<20 {
		return
	}
	c.codeStart = start
	c.codeEnd = end
	c.icache = make([]decInsn, end-start)
	c.Mem.SetCodeWatch(start, end, func() {
		clear(c.icache)
	})
}

func (c *CPU) calcEA(ins *decInsn) uint32 {
	ea := ins.disp
	if ins.rm < 8 {
		ea += c.R[ins.rm]
	}
	if ins.index < 8 {
		ea += c.R[ins.index] << ins.scale
	}
	if (ins.flags & icFlagSegFS) != 0 {
		ea += c.FSBase
	}
	return ea
}

func (c *CPU) getReg8(idx uint8) byte {
	if idx < 4 {
		return byte(c.R[idx])
	}
	return byte(c.R[idx-4] >> 8)
}

func (c *CPU) setReg8(idx uint8, val byte) {
	if idx < 4 {
		c.R[idx] = (c.R[idx] &^ 0xFF) | uint32(val)
		return
	}
	r := idx - 4
	c.R[r] = (c.R[r] &^ 0xFF00) | (uint32(val) << 8)
}

func (c *CPU) alu32Fast(op uint8, a, b uint32) (uint32, bool) {
	switch op {
	case 0: // ADD
		res, nf := aluAdd32(a, b, 0, c.EFLAGS)
		c.EFLAGS = nf
		return res, true
	case 1: // OR
		res := a | b
		c.EFLAGS = aluLogic32(res, c.EFLAGS)
		return res, true
	case 2: // ADC
		res, nf := aluAdd32(a, b, c.EFLAGS&flagCF, c.EFLAGS)
		c.EFLAGS = nf
		return res, true
	case 3: // SBB
		res, nf := aluSub32(a, b, c.EFLAGS&flagCF, c.EFLAGS)
		c.EFLAGS = nf
		return res, true
	case 4: // AND
		res := a & b
		c.EFLAGS = aluLogic32(res, c.EFLAGS)
		return res, true
	case 5: // SUB
		res, nf := aluSub32(a, b, 0, c.EFLAGS)
		c.EFLAGS = nf
		return res, true
	case 6: // XOR
		res := a ^ b
		c.EFLAGS = aluLogic32(res, c.EFLAGS)
		return res, true
	case 7: // CMP
		_, nf := aluSub32(a, b, 0, c.EFLAGS)
		c.EFLAGS = nf
		return 0, false
	}
	return a, false
}

func (c *CPU) alu8Fast(op uint8, a, b byte) (byte, bool) {
	switch op {
	case 0: // ADD
		res, nf := aluAdd(uint32(a), uint32(b), 0, c.EFLAGS, 8)
		c.EFLAGS = nf
		return byte(res), true
	case 1: // OR
		res := a | b
		c.EFLAGS = aluLogic(uint32(res), c.EFLAGS, 8)
		return res, true
	case 2: // ADC
		res, nf := aluAdd(uint32(a), uint32(b), c.EFLAGS&flagCF, c.EFLAGS, 8)
		c.EFLAGS = nf
		return byte(res), true
	case 3: // SBB
		res, nf := aluSub(uint32(a), uint32(b), c.EFLAGS&flagCF, c.EFLAGS, 8)
		c.EFLAGS = nf
		return byte(res), true
	case 4: // AND
		res := a & b
		c.EFLAGS = aluLogic(uint32(res), c.EFLAGS, 8)
		return res, true
	case 5: // SUB
		res, nf := aluSub(uint32(a), uint32(b), 0, c.EFLAGS, 8)
		c.EFLAGS = nf
		return byte(res), true
	case 6: // XOR
		res := a ^ b
		c.EFLAGS = aluLogic(uint32(res), c.EFLAGS, 8)
		return res, true
	case 7: // CMP
		_, nf := aluSub(uint32(a), uint32(b), 0, c.EFLAGS, 8)
		c.EFLAGS = nf
		return 0, false
	}
	return a, false
}

func decodeModRMImg(img []byte, pos, imgLen int, segFS bool, out *decInsn) (int, bool) {
	if pos >= imgLen {
		return pos, false
	}
	b := img[pos]
	pos++
	mod := (b >> 6) & 3
	out.reg = (b >> 3) & 7
	rm := b & 7
	out.index = 0xFF
	out.scale = 0
	out.disp = 0
	if mod == 3 {
		out.flags |= icFlagIsReg
		out.rm = rm
		return pos, true
	}
	if rm == 4 {
		if pos >= imgLen {
			return pos, false
		}
		sib := img[pos]
		pos++
		out.scale = sib >> 6
		idx := (sib >> 3) & 7
		base := sib & 7
		if idx != 4 {
			out.index = idx
		}
		if base == 5 && mod == 0 {
			if pos+4 > imgLen {
				return pos, false
			}
			out.rm = 0xFF
			out.disp = le32(img, pos)
			pos += 4
		} else {
			out.rm = base
		}
	} else if mod == 0 && rm == 5 {
		if pos+4 > imgLen {
			return pos, false
		}
		out.rm = 0xFF
		out.disp = le32(img, pos)
		pos += 4
	} else {
		out.rm = rm
	}
	switch mod {
	case 1:
		if pos >= imgLen {
			return pos, false
		}
		out.disp = uint32(int32(int8(img[pos])))
		pos++
	case 2:
		if pos+4 > imgLen {
			return pos, false
		}
		out.disp = le32(img, pos)
		pos += 4
	}
	if segFS {
		out.flags |= icFlagSegFS
	}
	return pos, true
}

func (c *CPU) decodeIntoCache(eip uint32, out *decInsn) {
	*out = decInsn{kind: opFallback}
	img := c.Mem.img
	base := int(eip - c.Mem.imgBase)
	imgLen := int(c.Mem.imgLen)
	if base < 0 || base >= imgLen {
		return
	}
	pos := base
	segFS := false
	if img[pos] == 0x64 {
		segFS = true
		pos++
		if pos >= imgLen {
			return
		}
	}
	op := img[pos]
	pos++
	switch op {
	case 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65:
		return
	}

	finish := func(kind uint8, endPos int) {
		n := endPos - base
		if n <= 0 || n > 15 {
			out.kind = opFallback
			return
		}
		out.length = uint8(n)
		out.kind = kind
	}

	// 00..3F: 标准 ALU (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP)
	if op < 0x40 && (op&7) <= 5 {
		out.sub = (op >> 3) & 7
		sub := op & 7
		switch sub {
		case 0: // rm8, r8
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			if (out.flags & icFlagIsReg) != 0 {
				dst, src := out.rm, out.reg
				out.reg, out.rm = dst, src
				finish(opAlu8RR, p)
				return
			}
			finish(opAlu8MR, p)
			return
		case 1: // rm32, r32
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			if (out.flags & icFlagIsReg) != 0 {
				dst, src := out.rm, out.reg
				out.reg, out.rm = dst, src
				finish(opAlu32RR, p)
				return
			}
			finish(opAlu32MR, p)
			return
		case 2: // r8, rm8
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			if (out.flags & icFlagIsReg) != 0 {
				finish(opAlu8RR, p)
				return
			}
			finish(opAlu8RM, p)
			return
		case 3: // r32, rm32
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			if (out.flags & icFlagIsReg) != 0 {
				finish(opAlu32RR, p)
				return
			}
			finish(opAlu32RM, p)
			return
		case 4: // AL, imm8
			if pos >= imgLen {
				return
			}
			out.reg = regEAX
			out.imm = uint32(img[pos])
			finish(opAlu8RImm, pos+1)
			return
		case 5: // EAX, imm32
			if pos+4 > imgLen {
				return
			}
			out.reg = regEAX
			out.imm = le32(img, pos)
			finish(opAlu32RImm, pos+4)
			return
		}
	}

	switch {
	case op >= 0x40 && op <= 0x47: // INC r32
		out.reg = op & 7
		finish(opIncR32, pos)
		return
	case op >= 0x48 && op <= 0x4F: // DEC r32
		out.reg = op & 7
		finish(opDecR32, pos)
		return
	case op >= 0x50 && op <= 0x57: // PUSH r32
		out.reg = op & 7
		finish(opPushR32, pos)
		return
	case op >= 0x58 && op <= 0x5F: // POP r32
		out.reg = op & 7
		finish(opPopR32, pos)
		return
	case op >= 0x70 && op <= 0x7F: // Jcc rel8
		if pos >= imgLen {
			return
		}
		rel := int32(int8(img[pos]))
		endPos := pos + 1
		nextEIP := eip + uint32(endPos-base)
		out.sub = op & 0x0F
		out.disp = uint32(int32(nextEIP) + rel)
		finish(opJcc, endPos)
		return
	case op >= 0xB0 && op <= 0xB7: // MOV r8, imm8
		if pos >= imgLen {
			return
		}
		out.reg = op & 7
		out.imm = uint32(img[pos])
		finish(opMovR8Imm, pos+1)
		return
	case op >= 0xB8 && op <= 0xBF: // MOV r32, imm32
		if pos+4 > imgLen {
			return
		}
		out.reg = op & 7
		out.imm = le32(img, pos)
		finish(opMovR32Imm, pos+4)
		return
	}

	switch op {
	case 0x0F:
		if pos >= imgLen {
			return
		}
		op2 := img[pos]
		pos++
		switch {
		case op2 >= 0x80 && op2 <= 0x8F: // Jcc rel32
			if pos+4 > imgLen {
				return
			}
			rel := int32(le32(img, pos))
			endPos := pos + 4
			nextEIP := eip + uint32(endPos-base)
			out.sub = op2 & 0x0F
			out.disp = uint32(int32(nextEIP) + rel)
			finish(opJcc, endPos)
			return
		case op2 >= 0x90 && op2 <= 0x9F: // SETcc rm8
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			out.sub = op2 & 0x0F
			finish(opSetCC, p)
			return
		case op2 >= 0xC8 && op2 <= 0xCF: // BSWAP r32
			out.reg = op2 & 7
			finish(opBswap, pos)
			return
		case op2 == 0xB6: // MOVZX r32, rm8
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			finish(opMovZX8R32, p)
			return
		case op2 == 0xB7: // MOVZX r32, rm16
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			finish(opMovZX16R32, p)
			return
		case op2 == 0xBE: // MOVSX r32, rm8
			p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
			if !ok {
				return
			}
			finish(opMovSX8R32, p)
			return
		}
		return

	case 0x68: // PUSH imm32
		if pos+4 > imgLen {
			return
		}
		out.imm = le32(img, pos)
		finish(opPushImm32, pos+4)
		return
	case 0x6A: // PUSH imm8
		if pos >= imgLen {
			return
		}
		out.imm = uint32(int32(int8(img[pos])))
		finish(opPushImm32, pos+1)
		return

	case 0x80, 0x82: // Grp1 rm8, imm8
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok || p >= imgLen {
			return
		}
		out.sub = out.reg
		out.imm = uint32(img[p])
		if (out.flags & icFlagIsReg) != 0 {
			out.reg = out.rm
			finish(opAlu8RImm, p+1)
			return
		}
		finish(opAlu8MImm, p+1)
		return

	case 0x81: // Grp1 rm32, imm32
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok || p+4 > imgLen {
			return
		}
		out.sub = out.reg
		out.imm = le32(img, p)
		if (out.flags & icFlagIsReg) != 0 {
			out.reg = out.rm
			finish(opAlu32RImm, p+4)
			return
		}
		finish(opAlu32MImm, p+4)
		return

	case 0x83: // Grp1 rm32, signext imm8
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok || p >= imgLen {
			return
		}
		out.sub = out.reg
		out.imm = uint32(int32(int8(img[p])))
		if (out.flags & icFlagIsReg) != 0 {
			out.reg = out.rm
			finish(opAlu32RImm, p+1)
			return
		}
		finish(opAlu32MImm, p+1)
		return

	case 0x84: // TEST rm8, r8
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		finish(opTest8, p)
		return

	case 0x85: // TEST rm32, r32
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		if (out.flags & icFlagIsReg) != 0 {
			finish(opTest32RR, p)
			return
		}
		finish(opTest32RM, p)
		return

	case 0x88: // MOV rm8, r8
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		if (out.flags & icFlagIsReg) != 0 {
			dst, src := out.rm, out.reg
			out.reg, out.rm = dst, src
			finish(opMovR8R8, p)
			return
		}
		finish(opMovMR8, p)
		return

	case 0x89: // MOV rm32, r32
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		if (out.flags & icFlagIsReg) != 0 {
			dst, src := out.rm, out.reg
			out.reg, out.rm = dst, src
			finish(opMovR32R32, p)
			return
		}
		finish(opMovMR32, p)
		return

	case 0x8A: // MOV r8, rm8
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		if (out.flags & icFlagIsReg) != 0 {
			finish(opMovR8R8, p)
			return
		}
		finish(opMovR8M, p)
		return

	case 0x8B: // MOV r32, rm32
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		if (out.flags & icFlagIsReg) != 0 {
			finish(opMovR32R32, p)
			return
		}
		finish(opMovR32M, p)
		return

	case 0x8D: // LEA r32, m (忽略 FS 段基址)
		p, ok := decodeModRMImg(img, pos, imgLen, false, out)
		if !ok || (out.flags&icFlagIsReg) != 0 {
			return
		}
		finish(opLea32, p)
		return

	case 0x90: // NOP
		finish(opNop, pos)
		return

	case 0xA8: // TEST AL, imm8
		if pos >= imgLen {
			return
		}
		out.flags |= icFlagIsReg | 0x80
		out.rm = regEAX
		out.imm = uint32(img[pos])
		finish(opTest8, pos+1)
		return

	case 0xA9: // TEST EAX, imm32
		if pos+4 > imgLen {
			return
		}
		out.flags |= icFlagIsReg
		out.rm = regEAX
		out.imm = le32(img, pos)
		finish(opTest32Imm, pos+4)
		return

	case 0xC0, 0xD0, 0xD2: // Shifts rm8
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		out.sub = out.reg
		if op == 0xC0 {
			if p >= imgLen {
				return
			}
			out.imm = uint32(img[p])
			finish(opShift8Imm, p+1)
			return
		}
		if op == 0xD0 {
			out.imm = 1
			finish(opShift8Imm, p)
			return
		}
		finish(opShift8CL, p)
		return

	case 0xC1, 0xD1, 0xD3: // Shifts rm32
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok {
			return
		}
		out.sub = out.reg
		if op == 0xC1 {
			if p >= imgLen {
				return
			}
			out.imm = uint32(img[p])
			finish(opShift32Imm, p+1)
			return
		}
		if op == 0xD1 {
			out.imm = 1
			finish(opShift32Imm, p)
			return
		}
		finish(opShift32CL, p)
		return

	case 0xC2: // RET imm16
		if pos+2 > imgLen {
			return
		}
		out.imm = uint32(le16(img, pos))
		finish(opRet, pos+2)
		return

	case 0xC3: // RET
		out.imm = 0
		finish(opRet, pos)
		return

	case 0xC6: // MOV rm8, imm8
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok || out.reg != 0 || p >= imgLen {
			return
		}
		out.imm = uint32(img[p])
		finish(opMovMImm8, p+1)
		return

	case 0xC7: // MOV rm32, imm32
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok || out.reg != 0 || p+4 > imgLen {
			return
		}
		out.imm = le32(img, p)
		finish(opMovMImm32, p+4)
		return

	case 0xE8: // CALL rel32
		if pos+4 > imgLen {
			return
		}
		rel := int32(le32(img, pos))
		endPos := pos + 4
		nextEIP := eip + uint32(endPos-base)
		out.disp = uint32(int32(nextEIP) + rel)
		finish(opCallRel, endPos)
		return

	case 0xE9: // JMP rel32
		if pos+4 > imgLen {
			return
		}
		rel := int32(le32(img, pos))
		endPos := pos + 4
		nextEIP := eip + uint32(endPos-base)
		out.disp = uint32(int32(nextEIP) + rel)
		finish(opJmpRel, endPos)
		return

	case 0xEB: // JMP rel8
		if pos >= imgLen {
			return
		}
		rel := int32(int8(img[pos]))
		endPos := pos + 1
		nextEIP := eip + uint32(endPos-base)
		out.disp = uint32(int32(nextEIP) + rel)
		finish(opJmpRel, endPos)
		return

	case 0xF6: // Grp3 rm8 (只缓存 TEST /0)
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok || out.reg > 1 || p >= imgLen {
			return
		}
		out.flags |= 0x80 // 标记 F6 带 imm8
		out.imm = uint32(img[p])
		finish(opTest8, p+1)
		return

	case 0xF7: // Grp3 rm32 (只缓存 TEST /0)
		p, ok := decodeModRMImg(img, pos, imgLen, segFS, out)
		if !ok || out.reg > 1 || p+4 > imgLen {
			return
		}
		out.imm = le32(img, p)
		finish(opTest32Imm, p+4)
		return
	}
}

func (c *CPU) runLoopFast() error {
	eip := c.EIP
	steps := c.Steps
	limit := c.StepLimit
	icache := c.icache
	codeStart := c.codeStart
	codeSpan := c.codeEnd - c.codeStart
	mem := c.Mem

	for eip != HaltAddr {
		if c.Exited {
			c.EIP = eip
			c.Steps = steps
			return ErrExitThread
		}
		if steps >= limit {
			c.EIP = eip
			c.Steps = steps
			return fmt.Errorf("x86emu step limit exceeded (%d) @EIP=0x%08x", steps, eip)
		}
		off := eip - codeStart
		if off >= codeSpan {
			c.EIP = eip
			c.Steps = steps
			if err := c.step(); err != nil {
				if errors.Is(err, ErrExitThread) {
					return ErrExitThread
				}
				return fmt.Errorf("@EIP=0x%08x (step=%d): %w", c.EIP, c.Steps, err)
			}
			eip = c.EIP
			steps = c.Steps
			continue
		}

		ins := &icache[off]
		if ins.kind == opUnvisited {
			c.decodeIntoCache(eip, ins)
		}
		if ins.kind == opFallback {
			c.EIP = eip
			c.Steps = steps
			if err := c.step(); err != nil {
				if errors.Is(err, ErrExitThread) {
					return ErrExitThread
				}
				return fmt.Errorf("@EIP=0x%08x (step=%d): %w", c.EIP, c.Steps, err)
			}
			eip = c.EIP
			steps = c.Steps
			continue
		}

		steps++
		switch ins.kind {
		case opNop:
			eip += uint32(ins.length)

		case opMovR32R32:
			c.R[ins.reg] = c.R[ins.rm]
			eip += uint32(ins.length)

		case opMovR32M:
			ea := c.calcEA(ins)
			v, ok := mem.fastRead32(ea)
			if !ok {
				goto memSlow
			}
			c.R[ins.reg] = v
			eip += uint32(ins.length)

		case opMovMR32:
			ea := c.calcEA(ins)
			if !mem.fastWrite32(ea, c.R[ins.reg]) {
				goto memSlow
			}
			eip += uint32(ins.length)

		case opMovR8R8:
			c.setReg8(ins.reg, c.getReg8(ins.rm))
			eip += uint32(ins.length)

		case opMovR8M:
			ea := c.calcEA(ins)
			v, ok := mem.fastRead8(ea)
			if !ok {
				goto memSlow
			}
			c.setReg8(ins.reg, v)
			eip += uint32(ins.length)

		case opMovMR8:
			ea := c.calcEA(ins)
			if !mem.fastWrite8(ea, c.getReg8(ins.reg)) {
				goto memSlow
			}
			eip += uint32(ins.length)

		case opMovZX8R32:
			if (ins.flags & icFlagIsReg) != 0 {
				c.R[ins.reg] = uint32(c.getReg8(ins.rm))
			} else {
				ea := c.calcEA(ins)
				v, ok := mem.fastRead8(ea)
				if !ok {
					goto memSlow
				}
				c.R[ins.reg] = uint32(v)
			}
			eip += uint32(ins.length)

		case opMovZX16R32:
			if (ins.flags & icFlagIsReg) != 0 {
				c.R[ins.reg] = c.R[ins.rm] & 0xFFFF
			} else {
				ea := c.calcEA(ins)
				v, ok := mem.fastRead16(ea)
				if !ok {
					goto memSlow
				}
				c.R[ins.reg] = uint32(v)
			}
			eip += uint32(ins.length)

		case opMovSX8R32:
			var v byte
			if (ins.flags & icFlagIsReg) != 0 {
				v = c.getReg8(ins.rm)
			} else {
				ea := c.calcEA(ins)
				var ok bool
				v, ok = mem.fastRead8(ea)
				if !ok {
					goto memSlow
				}
			}
			c.R[ins.reg] = uint32(int32(int8(v)))
			eip += uint32(ins.length)

		case opMovR32Imm:
			c.R[ins.reg] = ins.imm
			eip += uint32(ins.length)

		case opMovR8Imm:
			c.setReg8(ins.reg, byte(ins.imm))
			eip += uint32(ins.length)

		case opMovMImm32:
			if (ins.flags & icFlagIsReg) != 0 {
				c.R[ins.rm] = ins.imm
			} else {
				ea := c.calcEA(ins)
				if !mem.fastWrite32(ea, ins.imm) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opMovMImm8:
			if (ins.flags & icFlagIsReg) != 0 {
				c.setReg8(ins.rm, byte(ins.imm))
			} else {
				ea := c.calcEA(ins)
				if !mem.fastWrite8(ea, byte(ins.imm)) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opLea32:
			c.R[ins.reg] = c.calcEA(ins)
			eip += uint32(ins.length)

		case opAlu32RR:
			if res, wr := c.alu32Fast(ins.sub, c.R[ins.reg], c.R[ins.rm]); wr {
				c.R[ins.reg] = res
			}
			eip += uint32(ins.length)

		case opAlu32RM:
			ea := c.calcEA(ins)
			v, ok := mem.fastRead32(ea)
			if !ok {
				goto memSlow
			}
			if res, wr := c.alu32Fast(ins.sub, c.R[ins.reg], v); wr {
				c.R[ins.reg] = res
			}
			eip += uint32(ins.length)

		case opAlu32MR:
			ea := c.calcEA(ins)
			dst, ok := mem.fastRead32(ea)
			if !ok {
				goto memSlow
			}
			if res, wr := c.alu32Fast(ins.sub, dst, c.R[ins.reg]); wr {
				if !mem.fastWrite32(ea, res) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opAlu32RImm:
			if res, wr := c.alu32Fast(ins.sub, c.R[ins.reg], ins.imm); wr {
				c.R[ins.reg] = res
			}
			eip += uint32(ins.length)

		case opAlu32MImm:
			ea := c.calcEA(ins)
			dst, ok := mem.fastRead32(ea)
			if !ok {
				goto memSlow
			}
			if res, wr := c.alu32Fast(ins.sub, dst, ins.imm); wr {
				if !mem.fastWrite32(ea, res) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opAlu8RR:
			if res, wr := c.alu8Fast(ins.sub, c.getReg8(ins.reg), c.getReg8(ins.rm)); wr {
				c.setReg8(ins.reg, res)
			}
			eip += uint32(ins.length)

		case opAlu8RM:
			ea := c.calcEA(ins)
			v, ok := mem.fastRead8(ea)
			if !ok {
				goto memSlow
			}
			if res, wr := c.alu8Fast(ins.sub, c.getReg8(ins.reg), v); wr {
				c.setReg8(ins.reg, res)
			}
			eip += uint32(ins.length)

		case opAlu8MR:
			ea := c.calcEA(ins)
			dst, ok := mem.fastRead8(ea)
			if !ok {
				goto memSlow
			}
			if res, wr := c.alu8Fast(ins.sub, dst, c.getReg8(ins.reg)); wr {
				if !mem.fastWrite8(ea, res) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opAlu8RImm:
			if res, wr := c.alu8Fast(ins.sub, c.getReg8(ins.reg), byte(ins.imm)); wr {
				c.setReg8(ins.reg, res)
			}
			eip += uint32(ins.length)

		case opAlu8MImm:
			ea := c.calcEA(ins)
			dst, ok := mem.fastRead8(ea)
			if !ok {
				goto memSlow
			}
			if res, wr := c.alu8Fast(ins.sub, dst, byte(ins.imm)); wr {
				if !mem.fastWrite8(ea, res) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opIncR32:
			cf := c.EFLAGS & flagCF
			res, nf := aluAdd32(c.R[ins.reg], 1, 0, c.EFLAGS)
			c.EFLAGS = (nf &^ flagCF) | cf
			c.R[ins.reg] = res
			eip += uint32(ins.length)

		case opDecR32:
			cf := c.EFLAGS & flagCF
			res, nf := aluSub32(c.R[ins.reg], 1, 0, c.EFLAGS)
			c.EFLAGS = (nf &^ flagCF) | cf
			c.R[ins.reg] = res
			eip += uint32(ins.length)

		case opTest32RR:
			c.EFLAGS = aluLogic32(c.R[ins.rm]&c.R[ins.reg], c.EFLAGS)
			eip += uint32(ins.length)

		case opTest32RM:
			ea := c.calcEA(ins)
			v, ok := mem.fastRead32(ea)
			if !ok {
				goto memSlow
			}
			c.EFLAGS = aluLogic32(v&c.R[ins.reg], c.EFLAGS)
			eip += uint32(ins.length)

		case opTest32Imm:
			var v uint32
			if (ins.flags & icFlagIsReg) != 0 {
				v = c.R[ins.rm]
			} else {
				ea := c.calcEA(ins)
				var ok bool
				v, ok = mem.fastRead32(ea)
				if !ok {
					goto memSlow
				}
			}
			c.EFLAGS = aluLogic32(v&ins.imm, c.EFLAGS)
			eip += uint32(ins.length)

		case opTest8:
			var v byte
			if (ins.flags & icFlagIsReg) != 0 {
				v = c.getReg8(ins.rm)
			} else {
				ea := c.calcEA(ins)
				var ok bool
				v, ok = mem.fastRead8(ea)
				if !ok {
					goto memSlow
				}
			}
			var rhs byte
			if (ins.flags & 0x80) != 0 {
				rhs = byte(ins.imm)
			} else {
				rhs = c.getReg8(ins.reg)
			}
			c.EFLAGS = aluLogic(uint32(v&rhs), c.EFLAGS, 8)
			eip += uint32(ins.length)

		case opShift32Imm, opShift32CL:
			cnt := ins.imm
			if ins.kind == opShift32CL {
				cnt = c.R[regECX] & 0xFF
			}
			if (ins.flags & icFlagIsReg) != 0 {
				res, nf := aluShift32(ins.sub, c.R[ins.rm], cnt, c.EFLAGS)
				c.EFLAGS = nf
				c.R[ins.rm] = res
			} else {
				ea := c.calcEA(ins)
				dst, ok := mem.fastRead32(ea)
				if !ok {
					goto memSlow
				}
				res, nf := aluShift32(ins.sub, dst, cnt, c.EFLAGS)
				c.EFLAGS = nf
				if !mem.fastWrite32(ea, res) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opShift8Imm, opShift8CL:
			cnt := ins.imm
			if ins.kind == opShift8CL {
				cnt = c.R[regECX] & 0xFF
			}
			if (ins.flags & icFlagIsReg) != 0 {
				res, nf := aluShift(ins.sub, uint32(c.getReg8(ins.rm)), cnt, c.EFLAGS, 8)
				c.EFLAGS = nf
				c.setReg8(ins.rm, byte(res))
			} else {
				ea := c.calcEA(ins)
				dst, ok := mem.fastRead8(ea)
				if !ok {
					goto memSlow
				}
				res, nf := aluShift(ins.sub, uint32(dst), cnt, c.EFLAGS, 8)
				c.EFLAGS = nf
				if !mem.fastWrite8(ea, byte(res)) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opPushR32:
			esp := c.R[regESP] - 4
			if !mem.fastWrite32(esp, c.R[ins.reg]) {
				goto memSlow
			}
			c.R[regESP] = esp
			eip += uint32(ins.length)

		case opPopR32:
			esp := c.R[regESP]
			v, ok := mem.fastRead32(esp)
			if !ok {
				goto memSlow
			}
			c.R[regESP] = esp + 4
			c.R[ins.reg] = v
			eip += uint32(ins.length)

		case opPushImm32:
			esp := c.R[regESP] - 4
			if !mem.fastWrite32(esp, ins.imm) {
				goto memSlow
			}
			c.R[regESP] = esp
			eip += uint32(ins.length)

		case opJcc:
			if evalCC(c.EFLAGS, ins.sub) {
				eip = ins.disp
			} else {
				eip += uint32(ins.length)
			}

		case opJmpRel:
			tgt := ins.disp
			if tgt >= StubBase && tgt < StubBase+StubSize {
				c.EIP = eip
				c.Steps = steps
				if err := c.enterCall(tgt); err != nil {
					return fmt.Errorf("@EIP=0x%08x (step=%d): %w", c.EIP, c.Steps, err)
				}
				eip = c.EIP
			} else {
				eip = tgt
			}

		case opCallRel:
			esp := c.R[regESP] - 4
			retAddr := eip + uint32(ins.length)
			if !mem.fastWrite32(esp, retAddr) {
				goto memSlow
			}
			c.R[regESP] = esp
			tgt := ins.disp
			if tgt >= StubBase && tgt < StubBase+StubSize {
				c.EIP = retAddr
				c.Steps = steps
				if err := c.enterCall(tgt); err != nil {
					if errors.Is(err, ErrExitThread) {
						return ErrExitThread
					}
					return fmt.Errorf("@EIP=0x%08x (step=%d): %w", c.EIP, c.Steps, err)
				}
				eip = c.EIP
			} else {
				eip = tgt
			}

		case opRet:
			esp := c.R[regESP]
			retAddr, ok := mem.fastRead32(esp)
			if !ok {
				goto memSlow
			}
			c.R[regESP] = esp + 4 + ins.imm
			eip = retAddr

		case opSetCC:
			v := byte(0)
			if evalCC(c.EFLAGS, ins.sub) {
				v = 1
			}
			if (ins.flags & icFlagIsReg) != 0 {
				c.setReg8(ins.rm, v)
			} else {
				ea := c.calcEA(ins)
				if !mem.fastWrite8(ea, v) {
					goto memSlow
				}
			}
			eip += uint32(ins.length)

		case opBswap:
			v := c.R[ins.reg]
			c.R[ins.reg] = (v >> 24) | ((v >> 8) & 0xFF00) | ((v & 0xFF00) << 8) | (v << 24)
			eip += uint32(ins.length)

		default:
			goto memSlow
		}
		continue

	memSlow:
		steps--
		c.EIP = eip
		c.Steps = steps
		if err := c.step(); err != nil {
			if errors.Is(err, ErrExitThread) {
				return ErrExitThread
			}
			return fmt.Errorf("@EIP=0x%08x (step=%d): %w", c.EIP, c.Steps, err)
		}
		eip = c.EIP
		steps = c.Steps
	}

	c.EIP = eip
	c.Steps = steps
	return nil
}
