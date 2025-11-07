package sirenerr

import "fmt"

// Error captures contextual information for pipeline failures.
type Error struct {
	Op   string
	Msg  string
	Code int
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Op, e.Msg)
	}
	return fmt.Sprintf("%s: %s: %v", e.Op, e.Msg, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// E constructs an Error with the provided context.
func E(op, msg string, code int, err error) error {
	return &Error{Op: op, Msg: msg, Code: code, Err: err}
}
