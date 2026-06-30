package cobra

import (
	"context"
	"fmt"
	"os"
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
}

func (c *Command) Execute() error {
	if c.ctx == nil {
		c.ctx = context.Background()
	}
	return c.execute(os.Args[1:])
}

func (c *Command) execute(args []string) error {
	if len(args) > 0 {
		for _, child := range c.children {
			if child.commandName() == args[0] {
				child.ctx = c.ctx
				return child.execute(args[1:])
			}
		}
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
			strings: map[string]*string{},
			bools:   map[string]*bool{},
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

type FlagSet struct {
	strings map[string]*string
	bools   map[string]*bool
	args    []string
}

func (f *FlagSet) StringVar(p *string, name string, value string, usage string) {
	*p = value
	f.strings[name] = p
}

func (f *FlagSet) BoolVar(p *bool, name string, value bool, usage string) {
	*p = value
	f.bools[name] = p
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

func ExactArgs(n int) PositionalArgs {
	return func(cmd *Command, args []string) error {
		if len(args) != n {
			return fmt.Errorf("accepts %d arg(s), received %d", n, len(args))
		}
		return nil
	}
}
