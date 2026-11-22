// Package validate holds checksum validators. Phase 0 needs Luhn only (for the
// eval/mock generators); Phase 2 adds IBAN, ABA, Verhoeff, SSN rules here.
package validate

// Luhn reports whether s (ASCII digits only) passes the Luhn checksum.
// Non-digit input and strings shorter than 2 digits return false.
func Luhn(s string) bool {
	if len(s) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// LuhnCheckDigit returns the digit that makes prefix+digit Luhn-valid.
// prefix must be ASCII digits.
func LuhnCheckDigit(prefix string) byte {
	sum := 0
	double := true // the check digit will occupy the (undoubled) last slot
	for i := len(prefix) - 1; i >= 0; i-- {
		d := int(prefix[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return byte('0' + (10-sum%10)%10)
}
