package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"unicode/utf8"
)

const maxInt = 9007199254740991
const maxDepth = 32

type kind int

const (
	kObj kind = iota
	kArr
	kStr
	kInt
	kBool
	kNull
)

type val struct {
	k    kind
	s    string // string value (unescaped)
	n    int64
	b    bool
	keys []string
	vals []*val
	arr  []*val
}

type parser struct {
	b []byte
	i int
}

type perr struct{}

func (p *parser) fail() { panic(perr{}) }
func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}
func (p *parser) peek() byte {
	if p.i >= len(p.b) {
		p.fail()
	}
	return p.b[p.i]
}

func (p *parser) value(depth int) *val {
	p.ws()
	c := p.peek()
	switch {
	case c == '{':
		if depth+1 > maxDepth {
			p.fail()
		}
		p.i++
		v := &val{k: kObj}
		seen := map[string]bool{}
		p.ws()
		if p.peek() == '}' {
			p.i++
			return v
		}
		for {
			p.ws()
			if p.peek() != '"' {
				p.fail()
			}
			key := p.str()
			if seen[key] {
				p.fail()
			}
			seen[key] = true
			p.ws()
			if p.peek() != ':' {
				p.fail()
			}
			p.i++
			e := p.value(depth + 1)
			v.keys = append(v.keys, key)
			v.vals = append(v.vals, e)
			p.ws()
			c := p.peek()
			p.i++
			if c == ',' {
				continue
			}
			if c == '}' {
				return v
			}
			p.fail()
		}
	case c == '[':
		if depth+1 > maxDepth {
			p.fail()
		}
		p.i++
		v := &val{k: kArr}
		p.ws()
		if p.peek() == ']' {
			p.i++
			return v
		}
		for {
			e := p.value(depth + 1)
			v.arr = append(v.arr, e)
			p.ws()
			c := p.peek()
			p.i++
			if c == ',' {
				continue
			}
			if c == ']' {
				return v
			}
			p.fail()
		}
	case c == '"':
		return &val{k: kStr, s: p.str()}
	case c == 't':
		p.lit("true")
		return &val{k: kBool, b: true}
	case c == 'f':
		p.lit("false")
		return &val{k: kBool}
	case c == 'n':
		p.lit("null")
		return &val{k: kNull}
	case c == '-' || (c >= '0' && c <= '9'):
		return p.num()
	}
	p.fail()
	return nil
}

func (p *parser) lit(s string) {
	if bytes.HasPrefix(p.b[p.i:], []byte(s)) {
		p.i += len(s)
		return
	}
	p.fail()
}

func (p *parser) num() *val {
	st := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.b) {
		p.fail()
	}
	ds := p.i
	if p.b[p.i] == '0' {
		p.i++
	} else if p.b[p.i] >= '1' && p.b[p.i] <= '9' {
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
	} else {
		p.fail()
	}
	if p.i < len(p.b) {
		switch p.b[p.i] {
		case '.', 'e', 'E':
			p.fail()
		}
		// digit after leading 0 is also caught by the structure check (trailing garbage)
	}
	if p.i-ds > 16 {
		p.fail()
	}
	bi, ok := new(big.Int).SetString(string(p.b[st:p.i]), 10)
	if !ok || !bi.IsInt64() {
		p.fail()
	}
	n := bi.Int64()
	if n > maxInt || n < -maxInt {
		p.fail()
	}
	return &val{k: kInt, n: n}
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}

func (p *parser) str() string {
	p.i++ // opening quote
	var out []byte
	for {
		if p.i >= len(p.b) {
			p.fail()
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out)
		case c < 0x20:
			p.fail()
		case c == '\\':
			p.i++
			if p.i >= len(p.b) {
				p.fail()
			}
			e := p.b[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, 8)
			case 'f':
				out = append(out, 12)
			case 'n':
				out = append(out, 10)
			case 'r':
				out = append(out, 13)
			case 't':
				out = append(out, 9)
			case 'u':
				r, ok := hex4(p.b[p.i:])
				if !ok {
					p.fail()
				}
				p.i += 4
				if r >= 0xDC00 && r <= 0xDFFF {
					p.fail()
				}
				if r >= 0xD800 && r <= 0xDBFF {
					if p.i+1 < len(p.b) && p.b[p.i] == '\\' && p.b[p.i+1] == 'u' {
						r2, ok := hex4(p.b[p.i+2:])
						if !ok || r2 < 0xDC00 || r2 > 0xDFFF {
							p.fail()
						}
						p.i += 6
						r = 0x10000 + (r-0xD800)<<10 + (r2 - 0xDC00)
					} else {
						p.fail()
					}
				}
				out = utf8.AppendRune(out, r)
			default:
				p.fail()
			}
		default:
			out = append(out, c)
			p.i++
		}
	}
}

func get(v *val, k string) *val {
	for i, kk := range v.keys {
		if kk == k {
			return v.vals[i]
		}
	}
	return nil
}

// stepA returns the parsed answer or nil if refused.
func stepA(b []byte) (res *val) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(perr); ok {
				res = nil
				return
			}
			panic(r)
		}
	}()
	if len(b) > 1048576 || !utf8.Valid(b) {
		return nil
	}
	p := &parser{b: b}
	p.ws()
	if p.i >= len(b) || b[p.i] != '{' {
		return nil
	}
	v := p.value(0)
	p.ws()
	if p.i != len(b) {
		return nil
	}
	if len(v.keys) != 4 {
		return nil
	}
	vd, rs, ev, es := get(v, "verdict"), get(v, "reasons"), get(v, "evidence"), get(v, "escalate")
	if vd == nil || rs == nil || ev == nil || es == nil {
		return nil
	}
	if vd.k != kStr || (vd.s != "pass" && vd.s != "retry" && vd.s != "terminal_breach") {
		return nil
	}
	if rs.k != kArr || len(rs.arr) > 16 {
		return nil
	}
	for _, r := range rs.arr {
		if r.k != kStr || utf8.RuneCountInString(r.s) > 500 {
			return nil
		}
	}
	if es.k != kBool {
		return nil
	}
	if ev.k != kObj {
		return nil
	}
	for i, k := range ev.keys {
		if k != "threshold-check" || ev.vals[i].k != kObj {
			return nil
		}
	}
	return v
}

func clears(doc interface{}) bool {
	m, ok := doc.(map[string]interface{})
	if !ok {
		return false
	}
	dt, ok := m["doc_type"].(string)
	if !ok || (dt != "paystub" && dt != "tax-return") {
		return false
	}
	n, ok := m["monthly_income_cents"].(json.Number)
	if !ok {
		return false
	}
	bi, ok := new(big.Int).SetString(n.String(), 10)
	if !ok {
		return false
	}
	return bi.Cmp(big.NewInt(450000)) >= 0
}

type req struct {
	Doc interface{} `json:"doc"`
	B64 string      `json:"answer_b64"`
}

func handle(line []byte) string {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var r req
	if err := dec.Decode(&r); err != nil {
		return `{"refused":true}`
	}
	raw, err := base64.StdEncoding.DecodeString(r.B64)
	if err != nil {
		return `{"refused":true}`
	}
	a := stepA(raw)
	if a == nil {
		return `{"refused":true}`
	}
	verdict := get(a, "verdict").s
	evNonEmpty := len(get(a, "evidence").keys) > 0
	if verdict == "pass" && !clears(r.Doc) {
		verdict = "retry"
	}
	if get(a, "escalate").b && verdict != "terminal_breach" {
		verdict = "retry"
	}
	ev := "[]"
	if verdict == "pass" && evNonEmpty {
		ev = `["threshold-check"]`
	}
	return `{"verdict":"` + verdict + `","evidence":` + ev + `}`
}

func main() {
	rd := bufio.NewReaderSize(os.Stdin, 1<<20)
	w := bufio.NewWriter(os.Stdout)
	for {
		line, err := rd.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			w.WriteString(handle(line) + "\n")
			w.Flush()
		}
		if err != nil {
			return
		}
	}
}
