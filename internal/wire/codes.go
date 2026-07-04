package wire

// SQLite result-code name↔number tables, single-sourced here so the server (which
// emits a symbolic name in a Hrana error) and the client (which recovers the
// numeric code from that name) cannot disagree. The extended set preserves the
// constraint subtype (UNIQUE vs FOREIGNKEY vs NOTNULL vs CHECK vs PRIMARYKEY) that
// the primary code alone collapses to a bare SQLITE_CONSTRAINT — an ORM error
// mapper needs the subtype to classify a violation.

var primaryNames = map[int]string{
	1:  "SQLITE_ERROR",
	5:  "SQLITE_BUSY",
	6:  "SQLITE_LOCKED",
	8:  "SQLITE_READONLY",
	9:  "SQLITE_INTERRUPT",
	11: "SQLITE_CORRUPT",
	19: "SQLITE_CONSTRAINT",
	20: "SQLITE_MISMATCH",
	23: "SQLITE_AUTH",
}

var extendedNames = map[int]string{
	2067: "SQLITE_CONSTRAINT_UNIQUE",
	1555: "SQLITE_CONSTRAINT_PRIMARYKEY",
	787:  "SQLITE_CONSTRAINT_FOREIGNKEY",
	1299: "SQLITE_CONSTRAINT_NOTNULL",
	275:  "SQLITE_CONSTRAINT_CHECK",
}

// nameToCode is the combined inverse (extended subtypes + primary codes), so a
// symbolic name recovers its numeric code regardless of which table defined it.
var nameToCode = func() map[string]int {
	m := make(map[string]int, len(primaryNames)+len(extendedNames))
	for code, name := range primaryNames {
		m[name] = code
	}
	for code, name := range extendedNames {
		m[name] = code
	}
	return m
}()

// CodeName maps a primary SQLite result code to its symbolic name; unknown codes
// fall back to SQLITE_ERROR.
func CodeName(primary int) string {
	if n, ok := primaryNames[primary]; ok {
		return n
	}
	return "SQLITE_ERROR"
}

// ExtendedCodeName maps an extended result code to its symbolic name, preserving
// the constraint subtype; codes outside the meaningful set fall back to the
// primary code's name (the low byte).
func ExtendedCodeName(extended int) string {
	if n, ok := extendedNames[extended]; ok {
		return n
	}
	return CodeName(extended & 0xff)
}

// CodeForName recovers the numeric code (extended when the name is a subtype, else
// primary) from a symbolic name, or 0 if unknown. Inverse of CodeName/ExtendedCodeName.
func CodeForName(name string) int { return nameToCode[name] }
