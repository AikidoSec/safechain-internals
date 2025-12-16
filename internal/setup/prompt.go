package setup

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type Prompter struct {
	reader io.Reader
	writer io.Writer
}

func NewPrompter(reader io.Reader, writer io.Writer) *Prompter {
	return &Prompter{
		reader: reader,
		writer: writer,
	}
}

func (p *Prompter) Confirm(message string) (bool, error) {
	fmt.Fprintf(p.writer, "%s [y/N]: ", message)

	scanner := bufio.NewScanner(p.reader)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, err
		}
		return false, nil
	}

	response := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return response == "y" || response == "yes", nil
}

func (p *Prompter) Print(format string, args ...any) {
	fmt.Fprintf(p.writer, format, args...)
}

func (p *Prompter) Println(args ...any) {
	fmt.Fprintln(p.writer, args...)
}
