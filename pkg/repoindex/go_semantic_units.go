package repoindex

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"sort"
)

type semanticBinding struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`
	Scope string `json:"scope"`
}

type semanticOperation struct {
	ID              int      `json:"id"`
	Kind            string   `json:"kind"`
	Line            int      `json:"line"`
	Column          int      `json:"column"`
	EndLine         int      `json:"endLine"`
	EndColumn       int      `json:"endColumn"`
	Ancestors       []int    `json:"ancestors"`
	Name            string   `json:"name,omitempty"`
	Method          string   `json:"method,omitempty"`
	ReceiverType    string   `json:"receiverType,omitempty"`
	ReceiverBinding string   `json:"receiverBinding,omitempty"`
	Operator        string   `json:"operator,omitempty"`
	SourceKind      string   `json:"sourceKind,omitempty"`
	SourceOperation int      `json:"sourceOperation,omitempty"`
	Targets         []string `json:"targets,omitempty"`
	References      []string `json:"references,omitempty"`
	pos             token.Pos
	end             token.Pos
	sourcePos       token.Pos
}

type semanticUnitData struct {
	Key        string              `json:"key"`
	Bindings   []semanticBinding   `json:"bindings"`
	Operations []semanticOperation `json:"operations"`
}

type semanticParsedGoFile struct {
	record *v2FileRecord
	file   *ast.File
}

// insertSemanticUnits stores language-neutral function operations. Language
// adapters own parsing and type resolution; policies query these operations.
func (state *v2BuildState) insertSemanticUnits() error {
	groups := map[string][]*v2FileRecord{}
	for index := range state.files {
		record := &state.files[index]
		if record.goFile == nil {
			continue
		}
		key := record.module + "\x00" + path.Dir(record.path) + "\x00" + record.goFile.Name.Name
		groups[key] = append(groups[key], record)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	tx, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`INSERT INTO semantic_units(file_id,symbol_id,language,kind,name,line,column,end_line,end_column,adapter,data) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, key := range keys {
		if err := state.insertGoSemanticPackage(statement, groups[key]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (state *v2BuildState) insertGoSemanticPackage(statement *sql.Stmt, records []*v2FileRecord) error {
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(records))
	parsed := make([]semanticParsedGoFile, 0, len(records))
	for _, record := range records {
		file, err := parser.ParseFile(fset, record.path, record.body, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		files = append(files, file)
		parsed = append(parsed, semanticParsedGoFile{record: record, file: file})
	}
	if len(files) == 0 {
		return nil
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	configuration := types.Config{Importer: importer.Default(), Error: func(error) {}}
	packagePath := records[0].module
	if packagePath == "" {
		packagePath = "adversary.local/fixture"
	}
	if directory := path.Dir(records[0].path); directory != "." {
		packagePath += "/" + directory
	}
	checked, _ := configuration.Check(packagePath, fset, files, info)
	if checked == nil {
		return nil
	}
	for _, source := range parsed {
		for _, declaration := range source.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			if err := state.insertGoSemanticFunction(statement, source.record, function, checked, fset, info); err != nil {
				return err
			}
		}
	}
	return nil
}

func (state *v2BuildState) insertGoSemanticFunction(statement *sql.Stmt, record *v2FileRecord, function *ast.FuncDecl, checked *types.Package, fset *token.FileSet, info *types.Info) error {
	objects := map[types.Object]semanticBinding{}
	addBinding := func(object types.Object) string {
		if object == nil {
			return ""
		}
		if existing, ok := objects[object]; ok {
			return existing.ID
		}
		position := fset.Position(object.Pos())
		id := record.path + ":" + position.String() + ":" + object.Name()
		scope := "unknown"
		if variable, ok := object.(*types.Var); ok {
			switch {
			case variable.IsField():
				scope = "field"
			case variable.Parent() == checked.Scope():
				scope = "package"
			case object.Pos() >= function.Type.Pos() && object.Pos() < function.Body.Pos():
				scope = "parameter"
			default:
				scope = "local"
			}
		}
		binding := semanticBinding{ID: id, Name: object.Name(), Type: semanticType(object.Type()), Scope: scope}
		objects[object] = binding
		return id
	}
	var operations []semanticOperation
	var calls []*ast.CallExpr
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			calls = append(calls, call)
		}
		return true
	})
	for _, call := range calls {
		position, end := fset.Position(call.Pos()), fset.Position(call.End())
		op := semanticOperation{Kind: "call", Line: position.Line, Column: position.Column, EndLine: end.Line, EndColumn: end.Column, pos: call.Pos(), end: call.End()}
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			op.Name = callee.Name
		case *ast.SelectorExpr:
			op.Name, op.Method = callee.Sel.Name, callee.Sel.Name
			op.ReceiverType = semanticType(info.Types[callee.X].Type)
			if identifier, ok := callee.X.(*ast.Ident); ok {
				op.ReceiverBinding = addBinding(info.Uses[identifier])
			}
		}
		operations = append(operations, op)
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			position, end := fset.Position(typed.Pos()), fset.Position(typed.End())
			op := semanticOperation{Kind: "assignment", Line: position.Line, Column: position.Column, EndLine: end.Line, EndColumn: end.Column, Operator: typed.Tok.String(), SourceKind: "expression", pos: typed.Pos(), end: typed.End()}
			if len(typed.Rhs) == 1 {
				if source, ok := typed.Rhs[0].(*ast.CallExpr); ok {
					op.SourceKind = "call"
					op.sourcePos = source.Pos()
				}
			}
			for _, expression := range typed.Lhs {
				if identifier, ok := expression.(*ast.Ident); ok {
					object := info.Uses[identifier]
					if object == nil {
						object = info.Defs[identifier]
					}
					op.Targets = append(op.Targets, addBinding(object))
				}
			}
			operations = append(operations, op)
		case *ast.ReturnStmt:
			position, end := fset.Position(typed.Pos()), fset.Position(typed.End())
			op := semanticOperation{Kind: "return", Line: position.Line, Column: position.Column, EndLine: end.Line, EndColumn: end.Column, pos: typed.Pos(), end: typed.End()}
			ast.Inspect(typed, func(child ast.Node) bool {
				if identifier, ok := child.(*ast.Ident); ok {
					if id := addBinding(info.Uses[identifier]); id != "" {
						op.References = appendUnique(op.References, id)
					}
				}
				return true
			})
			operations = append(operations, op)
		case *ast.IfStmt:
			position, end := fset.Position(typed.Cond.Pos()), fset.Position(typed.Cond.End())
			op := semanticOperation{Kind: "condition", Line: position.Line, Column: position.Column, EndLine: end.Line, EndColumn: end.Column, pos: typed.Cond.Pos(), end: typed.Cond.End()}
			ast.Inspect(typed.Cond, func(child ast.Node) bool {
				if identifier, ok := child.(*ast.Ident); ok {
					if id := addBinding(info.Uses[identifier]); id != "" {
						op.References = appendUnique(op.References, id)
					}
				}
				return true
			})
			operations = append(operations, op)
		}
		return true
	})
	sort.SliceStable(operations, func(i, j int) bool {
		if operations[i].pos == operations[j].pos {
			return operations[i].Kind < operations[j].Kind
		}
		return operations[i].pos < operations[j].pos
	})
	for index := range operations {
		operations[index].ID = index + 1
	}
	callIDsByPosition := make(map[token.Pos]int)
	for _, operation := range operations {
		if operation.Kind == "call" {
			callIDsByPosition[operation.pos] = operation.ID
		}
	}
	for index := range operations {
		if operations[index].sourcePos.IsValid() {
			operations[index].SourceOperation = callIDsByPosition[operations[index].sourcePos]
		}
		for _, parent := range operations {
			if parent.Kind == "call" && parent.ID != operations[index].ID && parent.pos < operations[index].pos && parent.end >= operations[index].end {
				operations[index].Ancestors = append(operations[index].Ancestors, parent.ID)
			}
		}
	}
	bindings := make([]semanticBinding, 0, len(objects))
	for _, binding := range objects {
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ID < bindings[j].ID })
	receiver := ""
	if function.Recv != nil && len(function.Recv.List) > 0 {
		receiver = semanticType(info.Types[function.Recv.List[0].Type].Type)
	}
	identity := record.module + "\n" + record.path + "\n" + receiver + "\n" + function.Name.Name
	digest := sha256.Sum256([]byte(identity))
	data := semanticUnitData{Key: "go:function:sha256:" + hex.EncodeToString(digest[:]), Bindings: bindings, Operations: operations}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	start, end := fset.Position(function.Pos()), fset.Position(function.End())
	var symbolID any
	for _, symbol := range state.byFileName[record.path+"\x00"+function.Name.Name] {
		if symbol.kind == "function" || symbol.kind == "method" {
			symbolID = symbol.id
			break
		}
	}
	if _, err := statement.Exec(record.id, symbolID, "go", "function", function.Name.Name, start.Line, start.Column, end.Line, end.Column, "go/types", string(raw)); err != nil {
		return err
	}
	state.semanticUnits++
	return nil
}

func semanticType(value types.Type) string {
	if value == nil {
		return ""
	}
	return types.TypeString(value, func(pkg *types.Package) string { return pkg.Name() })
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
