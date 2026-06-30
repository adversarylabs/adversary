package cobra

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type PositionalArgs func(cmd *Command, args []string) error

type Command struct {
	Use           string
	Short         string
	Example       string
	Args          PositionalArgs
	RunE          func(cmd *Command, args []string) error
	SilenceUsage  bool
	SilenceErrors bool

	parent   *Command
	children []*Command
	flags    *FlagSet
	ctx      context.Context
	out      io.Writer
}

func (c *Command) Execute() error {
	if c.ctx == nil {
		c.ctx = context.Background()
	}
	if c.out == nil {
		c.out = os.Stdout
	}
	return c.execute(os.Args[1:])
}

func (c *Command) execute(args []string) error {
	if len(args) > 0 {
		for _, child := range c.children {
			if child.commandName() == args[0] {
				child.ctx = c.ctx
				child.out = c.output()
				return child.execute(args[1:])
			}
		}
	}

	if hasHelpFlag(args) {
		c.printHelp(c.output())
		return nil
	}

	if c.flags != nil {
		if err := c.flags.Parse(args); err != nil {
			return err
		}
		args = c.flags.Args()
	}

	if c.Args != nil {
		if err := c.Args(c, args); err != nil {
			return err
		}
	}
	if c.RunE == nil {
		c.printHelp(c.output())
		return nil
	}
	return c.RunE(c, args)
}

func (c *Command) AddCommand(commands ...*Command) {
	for _, child := range commands {
		child.parent = c
		c.children = append(c.children, child)
	}
}

func (c *Command) Flags() *FlagSet {
	if c.flags == nil {
		c.flags = &FlagSet{
			strings:     map[string]*string{},
			bools:       map[string]*bool{},
			stringUsage: map[string]string{},
			boolUsage:   map[string]string{},
		}
	}
	return c.flags
}

func (c *Command) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	if c.parent != nil {
		return c.parent.Context()
	}
	return context.Background()
}

func (c *Command) commandName() string {
	for i, ch := range c.Use {
		if ch == ' ' || ch == '\t' {
			return c.Use[:i]
		}
	}
	return c.Use
}

func (c *Command) output() io.Writer {
	if c.out != nil {
		return c.out
	}
	if c.parent != nil {
		return c.parent.output()
	}
	return os.Stdout
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func (c *Command) printHelp(w io.Writer) {
	if c.Short != "" {
		fmt.Fprintln(w, c.Short)
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Usage:\n  %s", c.Use)
	if len(c.children) > 0 {
		fmt.Fprint(w, " <command>")
	}
	if c.flags != nil && c.flags.hasFlags() {
		fmt.Fprint(w, " [flags]")
	}
	fmt.Fprintln(w)

	if len(c.children) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Commands:")
		for _, child := range c.children {
			fmt.Fprintf(w, "  %-16s %s\n", child.commandName(), child.Short)
		}
	}

	if c.Example != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Examples:")
		fmt.Fprintln(w, c.Example)
	}

	if c.flags != nil && c.flags.hasFlags() {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Flags:")
		c.flags.printHelp(w)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use \"adversary <command> --help\" for more information about a command.")
}

type FlagSet struct {
	strings     map[string]*string
	bools       map[string]*bool
	stringUsage map[string]string
	boolUsage   map[string]string
	args        []string
}

func (f *FlagSet) StringVar(p *string, name string, value string, usage string) {
	*p = value
	f.strings[name] = p
	f.stringUsage[name] = usage
}

func (f *FlagSet) BoolVar(p *bool, name string, value bool, usage string) {
	*p = value
	f.bools[name] = p
	f.boolUsage[name] = usage
}

func (f *FlagSet) Parse(args []string) error {
	f.args = f.args[:0]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			f.args = append(f.args, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			f.args = append(f.args, arg)
			continue
		}

		nameValue := strings.TrimPrefix(arg, "--")
		name, value, hasValue := strings.Cut(nameValue, "=")
		if target, ok := f.bools[name]; ok {
			if hasValue {
				switch value {
				case "true":
					*target = true
				case "false":
					*target = false
				default:
					return fmt.Errorf("invalid boolean value %q for --%s", value, name)
				}
			} else {
				*target = true
			}
			continue
		}
		if target, ok := f.strings[name]; ok {
			if !hasValue {
				i++
				if i >= len(args) {
					return fmt.Errorf("flag needs an argument: --%s", name)
				}
				value = args[i]
			}
			*target = value
			continue
		}
		return fmt.Errorf("unknown flag: --%s", name)
	}
	return nil
}

func (f *FlagSet) Args() []string {
	return f.args
}

func (f *FlagSet) hasFlags() bool {
	return len(f.strings)+len(f.bools) > 0
}

func (f *FlagSet) printHelp(w io.Writer) {
	names := make([]string, 0, len(f.strings)+len(f.bools)+1)
	for name := range f.strings {
		names = append(names, name)
	}
	for name := range f.bools {
		names = append(names, name)
	}
	names = append(names, "help")
	sort.Strings(names)

	for _, name := range names {
		switch {
		case name == "help":
			fmt.Fprintf(w, "  --%-14s %s\n", name, "help for this command")
		case f.strings[name] != nil:
			fmt.Fprintf(w, "  --%-14s %s\n", name+" <value>", f.stringUsage[name])
		case f.bools[name] != nil:
			fmt.Fprintf(w, "  --%-14s %s\n", name, f.boolUsage[name])
		}
	}
}

func ExactArgs(n int) PositionalArgs {
	return func(cmd *Command, args []string) error {
		if len(args) != n {
			return fmt.Errorf("accepts %d arg(s), received %d", n, len(args))
		}
		return nil
	}
}
