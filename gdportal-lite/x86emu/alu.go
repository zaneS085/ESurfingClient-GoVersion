package x86emu

const (
	flagCF uint32 = 1 << 0
	flagPF uint32 = 1 << 2
	flagAF uint32 = 1 << 4
	flagZF uint32 = 1 << 6
	flagSF uint32 = 1 << 7
	flagDF uint32 = 1 << 10
	flagOF uint32 = 1 << 11

	arithMask = flagCF | flagPF | flagAF | flagZF | flagSF | flagOF
)

var parityTable [256]bool

func init() {
	for i := 0; i < 256; i++ {
		bits := 0
		for b := 0; b < 8; b++ {
			if (i>>b)&1 != 0 {
				bits++
			}
		}
		parityTable[i] = bits%2 == 0
	}
}

func widthMask(bits uint) uint32 {
	switch bits {
	case 8:
		return 0xFF
	case 16:
		return 0xFFFF
	default:
		return 0xFFFFFFFF
	}
}

func signBit(bits uint) uint32 {
	return uint32(1) << (bits - 1)
}

func signExt32(v uint32, bits uint) int32 {
	switch bits {
	case 8:
		return int32(int8(v))
	case 16:
		return int32(int16(v))
	default:
		return int32(v)
	}
}

func setSZP(eflags, res uint32, bits uint) uint32 {
	eflags &^= flagZF | flagSF | flagPF
	if res&widthMask(bits) == 0 {
		eflags |= flagZF
	}
	if res&signBit(bits) != 0 {
		eflags |= flagSF
	}
	if parityTable[byte(res)] {
		eflags |= flagPF
	}
	return eflags
}

func aluAdd(a, b, cfIn, eflags uint32, bits uint) (uint32, uint32) {
	mask := widthMask(bits)
	sb := signBit(bits)
	ua := a & mask
	ub := b & mask
	sum := uint64(ua) + uint64(ub) + uint64(cfIn&1)
	res := uint32(sum) & mask

	eflags &^= arithMask
	eflags = setSZP(eflags, res, bits)
	if sum > uint64(mask) {
		eflags |= flagCF
	}
	if ((^(ua ^ ub)) & (ua ^ res) & sb) != 0 {
		eflags |= flagOF
	}
	if ((ua ^ ub ^ res) & 0x10) != 0 {
		eflags |= flagAF
	}
	return res, eflags
}

func aluSub(a, b, cfIn, eflags uint32, bits uint) (uint32, uint32) {
	mask := widthMask(bits)
	sb := signBit(bits)
	ua := a & mask
	ub := b & mask
	diff := uint64(ua) - uint64(ub) - uint64(cfIn&1)
	res := uint32(diff) & mask

	eflags &^= arithMask
	eflags = setSZP(eflags, res, bits)
	if diff > uint64(mask) {
		eflags |= flagCF
	}
	if ((ua ^ ub) & (ua ^ res) & sb) != 0 {
		eflags |= flagOF
	}
	if ((ua ^ ub ^ res) & 0x10) != 0 {
		eflags |= flagAF
	}
	return res, eflags
}

func aluInc(a, eflags uint32, bits uint) (uint32, uint32) {
	cf := eflags & flagCF
	res, nf := aluAdd(a, 1, 0, eflags, bits)
	return res, (nf &^ flagCF) | cf
}

func aluDec(a, eflags uint32, bits uint) (uint32, uint32) {
	cf := eflags & flagCF
	res, nf := aluSub(a, 1, 0, eflags, bits)
	return res, (nf &^ flagCF) | cf
}

func aluNeg(a, eflags uint32, bits uint) (uint32, uint32) {
	res, nf := aluSub(0, a, 0, eflags, bits)
	if a&widthMask(bits) == 0 {
		nf &^= flagCF
	} else {
		nf |= flagCF
	}
	return res, nf
}

func aluLogic(res, eflags uint32, bits uint) uint32 {
	eflags &^= flagCF | flagOF | flagAF
	return setSZP(eflags, res&widthMask(bits), bits)
}

func aluShift(op uint8, val, count, eflags uint32, bits uint) (uint32, uint32) {
	mask := widthMask(bits)
	sb := signBit(bits)
	cnt := uint(count & 0x1F)
	if cnt == 0 {
		return val & mask, eflags
	}
	v := val & mask

	switch op {
	case 0: // ROL
		eff := cnt % bits
		res := v
		if eff > 0 {
			res = ((v << eff) | (v >> (bits - eff))) & mask
		}
		eflags &^= flagCF | flagOF
		if res&1 != 0 {
			eflags |= flagCF
		}
		if cnt == 1 {
			msb := (res & sb) != 0
			cf := (eflags & flagCF) != 0
			if msb != cf {
				eflags |= flagOF
			}
		}
		return res, eflags

	case 1: // ROR
		eff := cnt % bits
		res := v
		if eff > 0 {
			res = ((v >> eff) | (v << (bits - eff))) & mask
		}
		eflags &^= flagCF | flagOF
		if res&sb != 0 {
			eflags |= flagCF
		}
		if cnt == 1 {
			b1 := (res & sb) != 0
			b2 := (res & (sb >> 1)) != 0
			if b1 != b2 {
				eflags |= flagOF
			}
		}
		return res, eflags

	case 2: // RCL
		eff := cnt % (bits + 1)
		cf := (eflags & flagCF) != 0
		res := v
		for i := uint(0); i < eff; i++ {
			nextCF := (res & sb) != 0
			res = ((res << 1) | boolU32(cf)) & mask
			cf = nextCF
		}
		eflags &^= flagCF | flagOF
		if cf {
			eflags |= flagCF
		}
		if cnt == 1 && (((res & sb) != 0) != cf) {
			eflags |= flagOF
		}
		return res, eflags

	case 3: // RCR
		eff := cnt % (bits + 1)
		cf := (eflags & flagCF) != 0
		res := v
		for i := uint(0); i < eff; i++ {
			nextCF := (res & 1) != 0
			res = (res >> 1) | (boolU32(cf) << (bits - 1))
			cf = nextCF
		}
		eflags &^= flagCF | flagOF
		if cf {
			eflags |= flagCF
		}
		if cnt == 1 {
			b1 := (res & sb) != 0
			b2 := (res & (sb >> 1)) != 0
			if b1 != b2 {
				eflags |= flagOF
			}
		}
		return res, eflags

	case 4, 6: // SHL / SAL
		var cf bool
		var res uint32
		if cnt <= bits {
			cf = ((uint64(v) << (cnt - 1)) & uint64(sb)) != 0
			res = uint32((uint64(v) << cnt) & uint64(mask))
		}
		eflags &^= flagCF | flagOF | flagAF
		if cf {
			eflags |= flagCF
		}
		if cnt == 1 && (((res & sb) != 0) != cf) {
			eflags |= flagOF
		}
		return res, setSZP(eflags, res, bits)

	case 5: // SHR
		cf := ((uint64(v) >> (cnt - 1)) & 1) != 0
		res := uint32(uint64(v) >> cnt)
		eflags &^= flagCF | flagOF | flagAF
		if cf {
			eflags |= flagCF
		}
		if cnt == 1 && (v&sb != 0) {
			eflags |= flagOF
		}
		return res, setSZP(eflags, res, bits)

	case 7: // SAR
		sv := int64(signExt32(v, bits))
		cf := ((sv >> (cnt - 1)) & 1) != 0
		res := uint32(sv>>cnt) & mask
		eflags &^= flagCF | flagOF | flagAF
		if cf {
			eflags |= flagCF
		}
		return res, setSZP(eflags, res, bits)
	}
	return v, eflags
}

func aluShld(dst, src, count, eflags uint32, bits uint) (uint32, uint32) {
	cnt := uint(count & 0x1F)
	if bits == 16 {
		cnt %= 16
	}
	if cnt == 0 {
		return dst & widthMask(bits), eflags
	}
	mask := widthMask(bits)
	sb := signBit(bits)
	d := uint64(dst & mask)
	s := uint64(src & mask)
	res := uint32(((d << cnt) | (s >> (bits - cnt))) & uint64(mask))
	cf := ((d << (cnt - 1)) & uint64(sb)) != 0
	eflags &^= flagCF | flagOF | flagAF
	if cf {
		eflags |= flagCF
	}
	if cnt == 1 && (((res & sb) != 0) != ((d & uint64(sb)) != 0)) {
		eflags |= flagOF
	}
	return res, setSZP(eflags, res, bits)
}

func aluShrd(dst, src, count, eflags uint32, bits uint) (uint32, uint32) {
	cnt := uint(count & 0x1F)
	if bits == 16 {
		cnt %= 16
	}
	if cnt == 0 {
		return dst & widthMask(bits), eflags
	}
	mask := widthMask(bits)
	sb := signBit(bits)
	d := uint64(dst & mask)
	s := uint64(src & mask)
	res := uint32(((d >> cnt) | (s << (bits - cnt))) & uint64(mask))
	cf := ((d >> (cnt - 1)) & 1) != 0
	eflags &^= flagCF | flagOF | flagAF
	if cf {
		eflags |= flagCF
	}
	if cnt == 1 && (((res & sb) != 0) != ((d & uint64(sb)) != 0)) {
		eflags |= flagOF
	}
	return res, setSZP(eflags, res, bits)
}

func aluAdd32(a, b, cfIn, eflags uint32) (uint32, uint32) {
	sum := uint64(a) + uint64(b) + uint64(cfIn&1)
	res := uint32(sum)
	eflags &^= arithMask
	if res == 0 {
		eflags |= flagZF
	}
	if res&0x80000000 != 0 {
		eflags |= flagSF
	}
	if parityTable[byte(res)] {
		eflags |= flagPF
	}
	if sum > 0xFFFFFFFF {
		eflags |= flagCF
	}
	if ((^(a ^ b)) & (a ^ res) & 0x80000000) != 0 {
		eflags |= flagOF
	}
	if ((a ^ b ^ res) & 0x10) != 0 {
		eflags |= flagAF
	}
	return res, eflags
}

func aluSub32(a, b, cfIn, eflags uint32) (uint32, uint32) {
	diff := uint64(a) - uint64(b) - uint64(cfIn&1)
	res := uint32(diff)
	eflags &^= arithMask
	if res == 0 {
		eflags |= flagZF
	}
	if res&0x80000000 != 0 {
		eflags |= flagSF
	}
	if parityTable[byte(res)] {
		eflags |= flagPF
	}
	if diff > 0xFFFFFFFF {
		eflags |= flagCF
	}
	if ((a ^ b) & (a ^ res) & 0x80000000) != 0 {
		eflags |= flagOF
	}
	if ((a ^ b ^ res) & 0x10) != 0 {
		eflags |= flagAF
	}
	return res, eflags
}

func aluLogic32(res, eflags uint32) uint32 {
	eflags &^= arithMask
	if res == 0 {
		eflags |= flagZF
	}
	if res&0x80000000 != 0 {
		eflags |= flagSF
	}
	if parityTable[byte(res)] {
		eflags |= flagPF
	}
	return eflags
}

func aluShift32(op uint8, v, count, eflags uint32) (uint32, uint32) {
	cnt := uint(count & 0x1F)
	if cnt == 0 {
		return v, eflags
	}
	switch op {
	case 0: // ROL
		res := (v << cnt) | (v >> (32 - cnt))
		eflags &^= flagCF | flagOF
		if res&1 != 0 {
			eflags |= flagCF
		}
		if cnt == 1 && (((res & 0x80000000) != 0) != ((res & 1) != 0)) {
			eflags |= flagOF
		}
		return res, eflags
	case 1: // ROR
		res := (v >> cnt) | (v << (32 - cnt))
		eflags &^= flagCF | flagOF
		if res&0x80000000 != 0 {
			eflags |= flagCF
		}
		if cnt == 1 && (((res & 0x80000000) != 0) != ((res & 0x40000000) != 0)) {
			eflags |= flagOF
		}
		return res, eflags
	case 4, 6: // SHL / SAL
		cf := ((v >> (32 - cnt)) & 1) != 0
		res := v << cnt
		eflags = aluLogic32(res, eflags)
		if cf {
			eflags |= flagCF
		}
		if cnt == 1 && (((res & 0x80000000) != 0) != cf) {
			eflags |= flagOF
		}
		return res, eflags
	case 5: // SHR
		cf := ((v >> (cnt - 1)) & 1) != 0
		res := v >> cnt
		eflags = aluLogic32(res, eflags)
		if cf {
			eflags |= flagCF
		}
		if cnt == 1 && (v&0x80000000 != 0) {
			eflags |= flagOF
		}
		return res, eflags
	case 7: // SAR
		sv := int32(v)
		cf := ((sv >> (cnt - 1)) & 1) != 0
		res := uint32(sv >> cnt)
		eflags = aluLogic32(res, eflags)
		if cf {
			eflags |= flagCF
		}
		return res, eflags
	default:
		return aluShift(op, v, count, eflags, 32)
	}
}

func evalCC(ef uint32, cc byte) bool {
	cf := (ef & flagCF) != 0
	pf := (ef & flagPF) != 0
	zf := (ef & flagZF) != 0
	sf := (ef & flagSF) != 0
	of := (ef & flagOF) != 0
	switch cc & 0x0F {
	case 0x0:
		return of
	case 0x1:
		return !of
	case 0x2:
		return cf
	case 0x3:
		return !cf
	case 0x4:
		return zf
	case 0x5:
		return !zf
	case 0x6:
		return cf || zf
	case 0x7:
		return !cf && !zf
	case 0x8:
		return sf
	case 0x9:
		return !sf
	case 0xA:
		return pf
	case 0xB:
		return !pf
	case 0xC:
		return sf != of
	case 0xD:
		return sf == of
	case 0xE:
		return zf || (sf != of)
	case 0xF:
		return !zf && (sf == of)
	}
	return false
}

func boolU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
