package seekrit

// Secret references: ${OTHER_SECRET} inside a secret value.
//
// Expansion happens here, in-process, after the layers are merged — the API only
// ever holds the ciphertext of the literal ${OTHER_SECRET} text. The rules are
// fixed by the shared golden fixture (testdata/vectors.json, "interpolation"),
// which every seekrit client is tested against:
//
//   - ${NAME} becomes NAME's value from the same merged set, recursively.
//   - NAME must look like an environment variable ([A-Za-z_][A-Za-z0-9_]*);
//     anything else (${FOO:-bar}, ${1}) is left exactly as written.
//   - A name that is not in the set is left literal and listed in Unresolved, so
//     a stored value containing e.g. ${GITHUB_SHA} keeps working.
//   - $${NAME} is an escape for the literal text ${NAME}.
//   - A reference cycle returns a *ReferenceError.

import (
	"sort"
	"strings"
)

// maxExpandedLength caps a single expanded value: nested references can
// multiply length.
const maxExpandedLength = 1 << 20

// Interpolation is the outcome of expanding a variable set.
type Interpolation struct {
	// Values is the variable set with every reference expanded.
	Values map[string]string
	// Expanded lists names whose value had at least one reference expanded.
	Expanded []string
	// Unresolved lists referenced names that exist nowhere in the set, sorted.
	Unresolved []string
}

// isReferenceName reports whether name matches [A-Za-z_][A-Za-z0-9_]*.
func isReferenceName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_',
			c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// segment is a run of literal text, or one well-formed ${NAME} reference.
type segment struct {
	// reference is the referenced name, empty for a literal segment.
	reference string
	// text is the literal text, or the raw ${NAME} source of a reference.
	text string
}

// scan splits a value into literal runs and references — the single tokenizer
// the rules above are expressed in terms of. '$', '{' and '}' are ASCII, so
// every index here lands on a UTF-8 boundary.
func scan(text string) []segment {
	var out []segment
	i := 0
	for i < len(text) {
		offset := strings.IndexByte(text[i:], '$')
		if offset < 0 {
			out = append(out, segment{text: text[i:]})
			break
		}
		dollar := i + offset
		if dollar > i {
			out = append(out, segment{text: text[i:dollar]})
		}

		// `$${` — escape: the `${` is literal, and skipping all three bytes
		// means the `{NAME}` that follows can never be read as a reference.
		if strings.HasPrefix(text[dollar+1:], "${") {
			out = append(out, segment{text: "${"})
			i = dollar + 3
			continue
		}

		if strings.HasPrefix(text[dollar+1:], "{") {
			if rel := strings.IndexByte(text[dollar+2:], '}'); rel >= 0 {
				close := dollar + 2 + rel
				if name := text[dollar+2 : close]; isReferenceName(name) {
					out = append(out, segment{reference: name, text: text[dollar : close+1]})
					i = close + 1
					continue
				}
			}
		}

		// A plain '$', an unterminated `${`, or a non-name (${FOO:-bar}, ${1}):
		// literal. Advancing one byte lets a `${` later in the run still be
		// recognized.
		out = append(out, segment{text: text[dollar : dollar+1]})
		i = dollar + 1
	}
	return out
}

// InterpolateSecrets expands ${NAME} references throughout a merged variable
// set. The input map is never mutated. It returns a *ReferenceError only for
// cases with no possible answer: a reference cycle, or an expansion that grows
// without bound.
func InterpolateSecrets(values map[string]string) (Interpolation, error) {
	e := &expander{
		source:     values,
		resolved:   make(map[string]string, len(values)),
		unresolved: make(map[string]struct{}),
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic Expanded order and error reporting

	out := make(map[string]string, len(values))
	var expanded []string
	for _, name := range names {
		value, err := e.resolve(name)
		if err != nil {
			return Interpolation{}, err
		}
		out[name] = value
		if value != values[name] {
			expanded = append(expanded, name)
		}
	}

	unresolved := make([]string, 0, len(e.unresolved))
	for name := range e.unresolved {
		unresolved = append(unresolved, name)
	}
	sort.Strings(unresolved)

	return Interpolation{Values: out, Expanded: expanded, Unresolved: unresolved}, nil
}

// expander does depth-first expansion with memoization and cycle detection.
type expander struct {
	source     map[string]string
	resolved   map[string]string
	unresolved map[string]struct{}
	// stack is the chain currently being expanded — the cycle detector.
	stack []string
}

// resolve expands one present name's value, at most once per name.
func (e *expander) resolve(name string) (string, error) {
	if done, ok := e.resolved[name]; ok {
		return done, nil
	}
	for i, open := range e.stack {
		if open == name {
			chain := append(append([]string{}, e.stack[i:]...), name)
			return "", &ReferenceError{
				Code: ReferenceCycle,
				msg:  "secret reference cycle: " + strings.Join(chain, " -> "),
			}
		}
	}

	e.stack = append(e.stack, name)
	var b strings.Builder
	for _, seg := range scan(e.source[name]) {
		if seg.reference == "" {
			b.WriteString(seg.text)
			continue
		}
		if _, ok := e.source[seg.reference]; !ok {
			e.unresolved[seg.reference] = struct{}{}
			b.WriteString(seg.text)
			continue
		}
		value, err := e.resolve(seg.reference)
		if err != nil {
			return "", err
		}
		b.WriteString(value)
	}
	e.stack = e.stack[:len(e.stack)-1]

	out := b.String()
	if len(out) > maxExpandedLength {
		return "", &ReferenceError{
			Code: ReferenceTooLarge,
			msg:  name + ": expands beyond the maximum expanded length",
		}
	}
	e.resolved[name] = out
	return out, nil
}
