package telnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/modules/dictionary"
	"bytemomo/kraken/internal/native"
	cnd "bytemomo/trident/conduit"

	"github.com/sirupsen/logrus"
)

var defaultTelnetCreds = []dictionary.Credential{
	dictionary.NewCredential("admin", "admin", true),
	dictionary.NewCredential("admin", "1234", true),
	dictionary.NewCredential("admin", "12345", true),
	dictionary.NewCredential("root", "root", true),
	dictionary.NewCredential("root", "password", true),
	dictionary.NewCredential("root", "pass", true),
	dictionary.NewCredential("user", "user", true),
	dictionary.NewCredential("guest", "guest", true),
	dictionary.NewCredential("support", "support", true),
}

func Init() {
	registerDictionaryAttack()
}

func registerDictionaryAttack() {
	native.Register("telnet-dict-attack", native.Descriptor{
		Run:  runTelnetDictionaryAttack,
		Kind: cnd.KindStream,
		Stack: []domain.LayerHint{
			{Name: "tcp"},
		},
		Description: `Attempts to authenticate to a Telnet service using a credential dictionary.
Reports recovered username/password pairs and highlights default credentials when present.`,
	})
}

func runTelnetDictionaryAttack(ctx context.Context, mod *domain.Module, target domain.Target, res native.Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}
	if res.StreamFactory == nil {
		return result, errors.New("telnet-dict-attack requires a stream conduit")
	}

	opts, err := parseTelnetOptions(params)
	if err != nil {
		return result, err
	}

	logger := logrus.WithFields(logrus.Fields{
		"module": mod.ModuleID,
		"target": target.String(),
	})

	var lastErr error
	for _, cred := range opts.Credentials {
		runCtx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			runCtx, cancel = context.WithTimeout(ctx, timeout)
		}

		handle, cleanup, err := res.StreamFactory(runCtx)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return result, fmt.Errorf("dial conduit for credential %s/%s: %w", cred.Username, cred.Password, err)
		}

		stream, ok := handle.(cnd.Stream)
		if !ok {
			cleanup()
			if cancel != nil {
				cancel()
			}
			return result, fmt.Errorf("unexpected conduit type %T", handle)
		}

		client := newTelnetClient(runCtx, stream)
		if opts.PrimeWithNewline {
			_ = client.sendRaw("\r\n")
		}

		success, transcript, attemptErr := attemptTelnetLogin(client, cred, opts)
		cleanup()
		if cancel != nil {
			cancel()
		}

		if attemptErr != nil {
			lastErr = attemptErr
			logger.WithError(attemptErr).Warnf("credential %s/%s failed", cred.Username, cred.Password)
			result.Logs = append(result.Logs, fmt.Sprintf("[TELNET-DICT] %s/%s -> error: %v", cred.Username, cred.Password, attemptErr))
			continue
		}

		if success {
			logger.WithField("username", cred.Username).Info("dictionary attack succeeded")
			evidence := map[string]any{
				"username":   cred.Username,
				"password":   cred.Password,
				"transcript": truncateTranscript(transcript),
			}
			result.Findings = append(result.Findings, domain.Finding{
				ID:          "CREDS-FOUND",
				ModuleID:    mod.ModuleID,
				Success:     true,
				Title:       "Telnet credentials discovered",
				Severity:    "high",
				Description: fmt.Sprintf("Telnet service granted access with %s/%s.", cred.Username, cred.Password),
				Evidence:    evidence,
				Tags:        []domain.Tag{"protocol:telnet"},
				Timestamp:   time.Now().UTC(),
				Target:      target,
			})

			if cred.IsDefault {
				result.Findings = append(result.Findings, domain.Finding{
					ID:          "DEFAULT-CREDENTIALS",
					ModuleID:    mod.ModuleID,
					Success:     true,
					Title:       "Default Telnet credential accepted",
					Severity:    "high",
					Description: fmt.Sprintf("Telnet service accepted default credential %s/%s.", cred.Username, cred.Password),
					Evidence:    evidence,
					Tags:        []domain.Tag{"protocol:telnet"},
					Timestamp:   time.Now().UTC(),
					Target:      target,
				})
			}
			return result, nil
		}

		result.Logs = append(result.Logs, fmt.Sprintf("[TELNET-DICT] %s/%s -> rejected", cred.Username, cred.Password))
	}

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, domain.Finding{
			ID:          "CREDS-FOUND",
			ModuleID:    mod.ModuleID,
			Success:     false,
			Title:       "Telnet dictionary attack",
			Severity:    "info",
			Description: fmt.Sprintf("No Telnet credential matched after %d attempts.", len(opts.Credentials)),
			Tags:        []domain.Tag{"protocol:telnet"},
			Timestamp:   time.Now().UTC(),
			Target:      target,
		})
	}

	return result, lastErr
}

type telnetOptions struct {
	Credentials        []dictionary.Credential
	UsernamePrompts    []string
	PasswordPrompts    []string
	FailureMarkers     []string
	SuccessMarkers     []string
	LoginPromptTimeout time.Duration
	PostLoginWait      time.Duration
	PrimeWithNewline   bool
}

func parseTelnetOptions(params map[string]any) (telnetOptions, error) {
	opts := telnetOptions{
		UsernamePrompts:    []string{"login:", "username:", "user:"},
		PasswordPrompts:    []string{"password:"},
		FailureMarkers:     []string{"login incorrect", "authentication failure", "login failed", "incorrect", "denied"},
		SuccessMarkers:     []string{"last login", "$", "#", "> ", "busybox"},
		LoginPromptTimeout: 5 * time.Second,
		PostLoginWait:      3 * time.Second,
		PrimeWithNewline:   true,
	}

	if params != nil {
		if prompts, ok := parseStringList(params["username_prompts"]); len(prompts) > 0 && ok {
			opts.UsernamePrompts = prompts
		}
		if prompts, ok := parseStringList(params["password_prompts"]); len(prompts) > 0 && ok {
			opts.PasswordPrompts = prompts
		}
		if markers, ok := parseStringList(params["failure_markers"]); len(markers) > 0 && ok {
			opts.FailureMarkers = markers
		}
		if markers, ok := parseStringList(params["success_markers"]); len(markers) > 0 && ok {
			opts.SuccessMarkers = markers
		}
		if v, ok := parseDuration(params["login_timeout"]); ok {
			opts.LoginPromptTimeout = v
		}
		if v, ok := parseDuration(params["post_login_wait"]); ok {
			opts.PostLoginWait = v
		}
		if prime, ok := params["prime_newline"].(bool); ok {
			opts.PrimeWithNewline = prime
		}
	}

	creds, err := dictionary.LoadCredentials(params, defaultTelnetCreds)
	if err != nil {
		return opts, err
	}
	opts.Credentials = creds
	return opts, nil
}

func parseStringList(raw any) ([]string, bool) {
	var list []string
	switch v := raw.(type) {
	case []string:
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s != "" {
				list = append(list, s)
			}
		}
		return list, true
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					list = append(list, s)
				}
			}
		}
		return list, len(list) > 0
	case string:
		s := strings.TrimSpace(v)
		if s != "" {
			return []string{s}, true
		}
	}
	return nil, false
}

func parseDuration(raw any) (time.Duration, bool) {
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return 0, false
		}
		if dur, err := time.ParseDuration(v); err == nil {
			return dur, true
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second, true
		}
	case float64:
		if v > 0 {
			return time.Duration(v * float64(time.Second)), true
		}
	}
	return 0, false
}

func attemptTelnetLogin(client *telnetClient, cred dictionary.Credential, opts telnetOptions) (bool, string, error) {
	if cred.Username == "" {
		return false, "", errors.New("empty username not supported for telnet")
	}
	if _, err := client.waitForPrompt(opts.UsernamePrompts, opts.LoginPromptTimeout); err != nil {
		return false, "", err
	}
	if err := client.sendLine(cred.Username); err != nil {
		return false, "", err
	}
	if _, err := client.waitForPrompt(opts.PasswordPrompts, opts.LoginPromptTimeout); err != nil {
		return false, "", err
	}
	if err := client.sendLine(cred.Password); err != nil {
		return false, "", err
	}

	output, err := client.collectOutput(opts.PostLoginWait)
	if err != nil && !errors.Is(err, errReadTimeout) && !errors.Is(err, io.EOF) {
		return false, output, err
	}

	lower := strings.ToLower(output)
	if containsAny(lower, opts.FailureMarkers) || containsAny(lower, lowerList(opts.PasswordPrompts)) || containsAny(lower, lowerList(opts.UsernamePrompts)) {
		return false, output, nil
	}

	if containsAny(lower, opts.SuccessMarkers) || hasShellPrompt(output) {
		return true, output, nil
	}

	if strings.TrimSpace(output) == "" {
		return false, output, nil
	}

	return true, output, nil
}

func lowerList(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s != "" {
			out = append(out, strings.ToLower(s))
		}
	}
	return out
}

func containsAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		needle = strings.ToLower(needle)
		if needle != "" && strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

var errReadTimeout = errors.New("timeout collecting telnet output")

type telnetClient struct {
	ctx    context.Context
	stream cnd.Stream
}

func newTelnetClient(ctx context.Context, stream cnd.Stream) *telnetClient {
	return &telnetClient{ctx: ctx, stream: stream}
}

func (c *telnetClient) sendLine(line string) error {
	return c.sendRaw(line + "\r\n")
}

func (c *telnetClient) sendRaw(payload string) error {
	if payload == "" {
		return nil
	}
	_, _, err := c.stream.Send(c.ctx, []byte(payload), nil, nil)
	return err
}

func (c *telnetClient) waitForPrompt(prompts []string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var buf strings.Builder
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		chunk, err := c.readString(minDuration(remaining, 2*time.Second))
		if err != nil {
			return buf.String(), err
		}
		if chunk == "" {
			continue
		}
		buf.WriteString(chunk)
		lower := strings.ToLower(buf.String())
		for _, prompt := range prompts {
			promptLower := strings.ToLower(prompt)
			if promptLower != "" && strings.Contains(lower, promptLower) {
				return buf.String(), nil
			}
		}
	}
	return buf.String(), fmt.Errorf("timeout waiting for prompt (%v)", prompts)
}

func (c *telnetClient) collectOutput(duration time.Duration) (string, error) {
	deadline := time.Now().Add(duration)
	var buf strings.Builder
	var received bool

	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		chunk, err := c.readString(minDuration(remaining, 2*time.Second))
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				break
			}
			return buf.String(), err
		}
		if chunk == "" {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		received = true
		buf.WriteString(chunk)
	}

	if !received && buf.Len() == 0 {
		return "", errReadTimeout
	}
	return buf.String(), nil
}

func (c *telnetClient) readString(timeout time.Duration) (string, error) {
	ctx := c.ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(c.ctx, timeout)
		defer cancel()
	}
	chunk, err := c.stream.Recv(ctx, &cnd.RecvOptions{MaxBytes: 2048})
	if err != nil {
		return "", err
	}
	if chunk == nil || chunk.Data == nil {
		return "", io.EOF
	}
	data := append([]byte(nil), chunk.Data.Bytes()...)
	chunk.Data.Release()
	clean := c.filterTelnet(data)
	if len(clean) == 0 {
		return "", nil
	}
	text := bytes.ReplaceAll(clean, []byte("\r\n"), []byte("\n"))
	text = bytes.ReplaceAll(text, []byte("\r"), []byte("\n"))
	return string(text), nil
}

func (c *telnetClient) filterTelnet(data []byte) []byte {
	const (
		iac  = 255
		do   = 253
		dont = 254
		will = 251
		wont = 252
		sb   = 250
		se   = 240
	)

	buf := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b != iac {
			buf = append(buf, b)
			continue
		}
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		switch cmd {
		case iac:
			buf = append(buf, iac)
			i++
		case do, dont, will, wont:
			if i+2 >= len(data) {
				i = len(data)
				break
			}
			opt := data[i+2]
			c.respondNegotiation(cmd, opt)
			i += 2
		case sb:
			j := i + 2
			for j < len(data)-1 {
				if data[j] == iac && data[j+1] == se {
					break
				}
				j++
			}
			i = j + 1
		default:
			i++
		}
	}
	return buf
}

func (c *telnetClient) respondNegotiation(cmd byte, opt byte) {
	const (
		iac  = 255
		dont = 254
		wont = 252
		will = 251
		do   = 253
	)

	var resp []byte
	switch cmd {
	case do:
		resp = []byte{iac, wont, opt}
	case will:
		resp = []byte{iac, dont, opt}
	default:
		return
	}
	_, _, _ = c.stream.Send(c.ctx, resp, nil, nil)
}

func hasShellPrompt(output string) bool {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return false
	}
	lines := strings.Split(trimmed, "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if last == "" {
		return false
	}
	for _, suffix := range []string{"#", "$", ">", "%"} {
		if strings.HasSuffix(last, suffix) {
			return true
		}
	}
	return false
}

func truncateTranscript(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return s[:400] + "..."
	}
	return s
}

func minDuration(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}
