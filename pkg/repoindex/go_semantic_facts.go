package repoindex

import (
	"database/sql"
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"sort"
)

const goFallibleOnceFactKind = "go.fallible_once_initialization"

type goFallibleOnceFactData struct {
	Function                string `json:"function"`
	Guard                   string `json:"guard"`
	Value                   string `json:"value"`
	Error                   string `json:"error"`
	ExplicitResetAfterError bool   `json:"explicitResetAfterError"`
}

type parsedGoFactFile struct {
	record *v2FileRecord
	file   *ast.File
}

func (state *v2BuildState) insertSemanticFacts() error {
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

	transaction, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	statement, err := transaction.Prepare(`INSERT INTO semantic_facts(
file_id,symbol_id,kind,line,column,end_line,end_column,confidence,adapter,data
) VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer statement.Close()

	for _, key := range keys {
		if err := state.insertGoPackageFacts(statement, groups[key]); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func (state *v2BuildState) insertGoPackageFacts(statement *sql.Stmt, records []*v2FileRecord) error {
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(records))
	parsed := make([]parsedGoFactFile, 0, len(records))
	for _, record := range records {
		file, err := parser.ParseFile(fset, record.path, record.body, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		files = append(files, file)
		parsed = append(parsed, parsedGoFactFile{record: record, file: file})
	}
	if len(files) == 0 {
		return nil
	}
	info := &types.Info{
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
		Types: map[ast.Expr]types.TypeAndValue{},
	}
	configuration := types.Config{
		Importer: importer.Default(),
		Error:    func(error) {},
	}
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
			if err := state.insertGoFunctionFacts(statement, source.record, function, checked, fset, info); err != nil {
				return err
			}
		}
	}
	return nil
}

func (state *v2BuildState) insertGoFunctionFacts(statement *sql.Stmt, record *v2FileRecord, function *ast.FuncDecl, checked *types.Package, fset *token.FileSet, info *types.Info) error {
	var calls []*ast.CallExpr
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		guard, bare := selectorXIdentifier(selector)
		if !bare || selector.Sel.Name != "Do" || !isPackageSyncOnce(info.Uses[guard], checked) {
			return true
		}
		if _, ok := call.Args[0].(*ast.FuncLit); ok {
			calls = append(calls, call)
		}
		return true
	})

	for _, call := range calls {
		selector := call.Fun.(*ast.SelectorExpr)
		guard := selector.X.(*ast.Ident)
		guardObject := info.Uses[guard]
		callback := call.Args[0].(*ast.FuncLit)
		assignments := persistentFallibleAssignments(callback, info, checked)
		for _, assignment := range assignments {
			if !returnsBindingsAfter(function.Body, call.End(), assignment.valueObject, assignment.errorObject, info) {
				continue
			}
			data := goFallibleOnceFactData{
				Function: function.Name.Name,
				Guard:    guard.Name,
				Value:    assignment.value.Name,
				Error:    assignment.failure.Name,
				ExplicitResetAfterError: resetsGuardAfterError(
					function.Body,
					call.End(),
					guardObject,
					assignment.errorObject,
					info,
				),
			}
			raw, err := json.Marshal(data)
			if err != nil {
				return err
			}
			start := fset.Position(call.Pos())
			end := fset.Position(call.End())
			var symbolID any
			for _, symbol := range state.byFileName[record.path+"\x00"+function.Name.Name] {
				if symbol.kind == "function" || symbol.kind == "method" {
					symbolID = symbol.id
					break
				}
			}
			if _, err := statement.Exec(record.id, symbolID, goFallibleOnceFactKind, start.Line, start.Column, end.Line, end.Column, 1.0, "go/types", string(raw)); err != nil {
				return err
			}
			state.facts++
		}
	}
	return nil
}

type goFallibleAssignment struct {
	value       *ast.Ident
	failure     *ast.Ident
	valueObject types.Object
	errorObject types.Object
}

func persistentFallibleAssignments(callback *ast.FuncLit, info *types.Info, checked *types.Package) []goFallibleAssignment {
	var assignments []goFallibleAssignment
	ast.Inspect(callback.Body, func(node ast.Node) bool {
		if nested, ok := node.(*ast.FuncLit); ok && nested != callback {
			return false
		}
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
			return true
		}
		if _, ok := assignment.Rhs[0].(*ast.CallExpr); !ok {
			return true
		}
		value, valueOK := assignment.Lhs[0].(*ast.Ident)
		failure, failureOK := assignment.Lhs[1].(*ast.Ident)
		if !valueOK || !failureOK {
			return true
		}
		valueObject := info.Uses[value]
		errorObject := info.Uses[failure]
		if !isPackageVariable(valueObject, checked) || !isPackageVariable(errorObject, checked) || !isErrorType(errorObject.Type()) {
			return true
		}
		assignments = append(assignments, goFallibleAssignment{value: value, failure: failure, valueObject: valueObject, errorObject: errorObject})
		return true
	})
	return assignments
}

func selectorXIdentifier(selector *ast.SelectorExpr) (*ast.Ident, bool) {
	identifier, ok := selector.X.(*ast.Ident)
	return identifier, ok
}

func isPackageVariable(object types.Object, checked *types.Package) bool {
	variable, ok := object.(*types.Var)
	return ok && variable.Parent() == checked.Scope()
}

func isPackageSyncOnce(object types.Object, checked *types.Package) bool {
	if !isPackageVariable(object, checked) {
		return false
	}
	named, ok := types.Unalias(object.Type()).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Once"
}

func isErrorType(value types.Type) bool {
	errorType := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	return types.Implements(value, errorType)
}

func returnsBindingsAfter(body *ast.BlockStmt, after token.Pos, valueObject, errorObject types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		statement, ok := node.(*ast.ReturnStmt)
		if !ok || statement.Pos() <= after || len(statement.Results) != 2 {
			return true
		}
		value, valueOK := statement.Results[0].(*ast.Ident)
		failure, failureOK := statement.Results[1].(*ast.Ident)
		found = valueOK && failureOK && info.Uses[value] == valueObject && info.Uses[failure] == errorObject
		return !found
	})
	return found
}

func resetsGuardAfterError(body *ast.BlockStmt, after token.Pos, guardObject, errorObject types.Object, info *types.Info) bool {
	reset := false
	ast.Inspect(body, func(node ast.Node) bool {
		if reset {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		statement, ok := node.(*ast.IfStmt)
		if !ok || statement.Pos() <= after || !expressionUsesObject(statement.Cond, errorObject, info) {
			return true
		}
		ast.Inspect(statement.Body, func(child ast.Node) bool {
			assignment, ok := child.(*ast.AssignStmt)
			if !ok || assignment.Tok != token.ASSIGN {
				return true
			}
			for _, left := range assignment.Lhs {
				identifier, ok := left.(*ast.Ident)
				if ok && info.Uses[identifier] == guardObject {
					reset = true
					return false
				}
			}
			return !reset
		})
		return !reset
	})
	return reset
}

func expressionUsesObject(expression ast.Expr, object types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && info.Uses[identifier] == object {
			found = true
			return false
		}
		return !found
	})
	return found
}
