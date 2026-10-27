package flow

import (
	"strconv"

	"ManScan/pkg/protocols"
	templateTypes "ManScan/pkg/templates/types"
	"github.com/projectdiscovery/goja/ast"
	"github.com/projectdiscovery/goja/parser"
)

// EstimateRequests returns a conservative static request estimate for a flow.
// Statically sized loops and the largest mutually exclusive branch are included.
func EstimateRequests(requests []protocols.Request, source string) int {
	program, err := parser.ParseFile(nil, "", source, 0)
	if err != nil {
		return baseRequestCount(requests)
	}

	estimator := requestEstimator{requests: make(map[string][]protocols.Request)}
	for _, request := range requests {
		protocol := request.Type().String()
		if request.Type() == templateTypes.OfflineHTTPProtocol {
			protocol = templateTypes.HTTPProtocol.String()
		}
		estimator.requests[protocol] = append(estimator.requests[protocol], request)
	}

	count := estimator.statements(program.Body)
	if count < baseRequestCount(requests) {
		return baseRequestCount(requests)
	}
	return count
}

type requestEstimator struct {
	requests map[string][]protocols.Request
}

func baseRequestCount(requests []protocols.Request) int {
	count := 0
	for _, request := range requests {
		count += request.Requests()
	}
	return count
}

func (e requestEstimator) statements(statements []ast.Statement) int {
	count := 0
	for _, statement := range statements {
		count += e.statement(statement)
	}
	return count
}

func (e requestEstimator) statement(statement ast.Statement) int {
	switch statement := statement.(type) {
	case *ast.BlockStatement:
		return e.statements(statement.List)
	case *ast.ExpressionStatement:
		return e.expression(statement.Expression)
	case *ast.VariableStatement:
		return e.bindings(statement.List)
	case *ast.LexicalDeclaration:
		return e.bindings(statement.List)
	case *ast.IfStatement:
		branches := e.statement(statement.Consequent)
		if statement.Alternate != nil {
			if alternate := e.statement(statement.Alternate); alternate > branches {
				branches = alternate
			}
		}
		return e.expression(statement.Test) + branches
	case *ast.ForOfStatement:
		return e.expression(statement.Source) + e.statement(statement.Body)*staticIterationCount(statement.Source)
	case *ast.ForInStatement:
		return e.statement(statement.Body)*staticIterationCount(statement.Source) + expressionForInto(e, statement.Into)
	case *ast.ForStatement:
		return e.forInitializer(statement.Initializer) + e.expression(statement.Test) + e.expression(statement.Update) + e.statement(statement.Body)
	case *ast.WhileStatement:
		return e.expression(statement.Test) + e.statement(statement.Body)
	case *ast.DoWhileStatement:
		return e.statement(statement.Body) + e.expression(statement.Test)
	case *ast.SwitchStatement:
		count := e.expression(statement.Discriminant)
		branchCount := 0
		for _, branch := range statement.Body {
			branchCount += e.expression(branch.Test) + e.statements(branch.Consequent)
		}
		return count + branchCount
	case *ast.TryStatement:
		body := e.statement(statement.Body)
		if statement.Catch != nil {
			if catcher := e.statement(statement.Catch.Body); catcher > body {
				body = catcher
			}
		}
		return body + e.statement(statement.Finally)
	case *ast.ReturnStatement:
		return e.expression(statement.Argument)
	case *ast.ThrowStatement:
		return e.expression(statement.Argument)
	case *ast.LabelledStatement:
		return e.statement(statement.Statement)
	default:
		return 0
	}
}

func (e requestEstimator) bindings(bindings []*ast.Binding) int {
	count := 0
	for _, binding := range bindings {
		count += e.expression(binding.Initializer)
	}
	return count
}

func (e requestEstimator) forInitializer(initializer ast.ForLoopInitializer) int {
	switch initializer := initializer.(type) {
	case *ast.ForLoopInitializerExpression:
		return e.expression(initializer.Expression)
	case *ast.ForLoopInitializerLexicalDecl:
		return e.bindings(initializer.LexicalDeclaration.List)
	case *ast.ForLoopInitializerVarDeclList:
		return e.bindings(initializer.List)
	default:
		return 0
	}
}

func expressionForInto(e requestEstimator, into ast.ForInto) int {
	if expression, ok := into.(*ast.ForIntoExpression); ok {
		return e.expression(expression.Expression)
	}
	return 0
}

func staticIterationCount(source ast.Expression) int {
	switch source := source.(type) {
	case *ast.ArrayLiteral:
		return len(source.Value)
	case *ast.ObjectLiteral:
		return len(source.Value)
	default:
		return 1
	}
}

func (e requestEstimator) expression(expression ast.Expression) int {
	switch expression := expression.(type) {
	case *ast.CallExpression:
		count := 0
		if identifier, ok := expression.Callee.(*ast.Identifier); ok {
			if requests, ok := e.requests[identifier.Name.String()]; ok {
				count += e.protocolCall(requests, expression.ArgumentList)
			} else {
				count += e.expression(expression.Callee)
			}
		} else {
			count += e.expression(expression.Callee)
		}
		for _, argument := range expression.ArgumentList {
			count += e.expression(argument)
		}
		return count
	case *ast.BinaryExpression:
		return e.expression(expression.Left) + e.expression(expression.Right)
	case *ast.ConditionalExpression:
		consequent := e.expression(expression.Consequent)
		if alternate := e.expression(expression.Alternate); alternate > consequent {
			consequent = alternate
		}
		return e.expression(expression.Test) + consequent
	case *ast.SequenceExpression:
		count := 0
		for _, item := range expression.Sequence {
			count += e.expression(item)
		}
		return count
	case *ast.UnaryExpression:
		return e.expression(expression.Operand)
	case *ast.ArrayLiteral:
		count := 0
		for _, item := range expression.Value {
			count += e.expression(item)
		}
		return count
	case *ast.ObjectLiteral:
		count := 0
		for _, property := range expression.Value {
			if keyed, ok := property.(*ast.PropertyKeyed); ok {
				count += e.expression(keyed.Value)
			}
		}
		return count
	case *ast.BracketExpression:
		return e.expression(expression.Left) + e.expression(expression.Member)
	case *ast.DotExpression:
		return e.expression(expression.Left)
	case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
		return 0
	default:
		return 0
	}
}

func (e requestEstimator) protocolCall(requests []protocols.Request, arguments []ast.Expression) int {
	if len(arguments) == 0 {
		count := 0
		for _, request := range requests {
			count += request.Requests()
		}
		return count
	}

	count := 0
	for _, argument := range arguments {
		selector, known := requestSelector(argument)
		if !known {
			maxRequestCount := 0
			for _, request := range requests {
				if request.Requests() > maxRequestCount {
					maxRequestCount = request.Requests()
				}
			}
			count += maxRequestCount
			continue
		}
		for index, request := range requests {
			if selector == strconv.Itoa(index+1) || (request.GetID() != "" && selector == request.GetID()) {
				count += request.Requests()
				break
			}
		}
	}
	return count
}

func requestSelector(expression ast.Expression) (string, bool) {
	switch expression := expression.(type) {
	case *ast.StringLiteral:
		return expression.Value.String(), true
	case *ast.NumberLiteral:
		if value, ok := expression.Value.(float64); ok {
			return strconv.FormatFloat(value, 'f', -1, 64), true
		}
		return expression.Literal, true
	default:
		return "", false
	}
}
