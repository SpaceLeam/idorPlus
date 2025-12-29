package graphql

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"idorplus/pkg/client"

	"github.com/go-resty/resty/v2"
)

// GraphQLTester handles GraphQL-specific IDOR testing
type GraphQLTester struct {
	client   *client.SmartClient
	endpoint string
}

// GraphQLQuery represents a GraphQL query
type GraphQLQuery struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	OperationName string                 `json:"operationName,omitempty"`
}

// IntrospectionResult holds introspection data
type IntrospectionResult struct {
	Types     []GraphQLType `json:"types"`
	Queries   []GraphQLField
	Mutations []GraphQLField
}

// GraphQLType represents a GraphQL type
type GraphQLType struct {
	Name   string         `json:"name"`
	Fields []GraphQLField `json:"fields"`
}

// GraphQLField represents a GraphQL field
type GraphQLField struct {
	Name string `json:"name"`
	Args []struct {
		Name string `json:"name"`
		Type struct {
			Name string `json:"name"`
		} `json:"type"`
	} `json:"args"`
}

// NewGraphQLTester creates a new GraphQL tester
func NewGraphQLTester(c *client.SmartClient, endpoint string) *GraphQLTester {
	return &GraphQLTester{
		client:   c,
		endpoint: endpoint,
	}
}

// Introspect performs GraphQL introspection to discover schema
func (gt *GraphQLTester) Introspect() (*IntrospectionResult, error) {
	query := GraphQLQuery{
		Query: `
		query IntrospectionQuery {
			__schema {
				queryType { name }
				mutationType { name }
				types {
					name
					fields {
						name
						args {
							name
							type { name }
						}
					}
				}
			}
		}`,
	}

	resp, err := gt.executeQuery(query)
	if err != nil {
		return nil, err
	}

	// Parse response
	var result struct {
		Data struct {
			Schema struct {
				Types []GraphQLType `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	// Extract queries with ID arguments (potential IDOR)
	ir := &IntrospectionResult{
		Types: result.Data.Schema.Types,
	}

	for _, t := range result.Data.Schema.Types {
		for _, f := range t.Fields {
			for _, arg := range f.Args {
				if isIDArgument(arg.Name) {
					ir.Queries = append(ir.Queries, f)
				}
			}
		}
	}

	return ir, nil
}

// TestIDOROnQuery tests a specific GraphQL query for IDOR
func (gt *GraphQLTester) TestIDOROnQuery(queryName string, idArgName string, validID, invalidID string) (*IDORResult, error) {
	// Build query with valid ID (baseline)
	validQuery := GraphQLQuery{
		Query: fmt.Sprintf(`query { %s(%s: "%s") { id } }`, queryName, idArgName, validID),
	}

	validResp, err := gt.executeQuery(validQuery)
	if err != nil {
		return nil, err
	}

	// Build query with invalid/other user's ID
	invalidQuery := GraphQLQuery{
		Query: fmt.Sprintf(`query { %s(%s: "%s") { id } }`, queryName, idArgName, invalidID),
	}

	invalidResp, err := gt.executeQuery(invalidQuery)
	if err != nil {
		return nil, err
	}

	result := &IDORResult{
		QueryName:     queryName,
		ValidStatus:   validResp.StatusCode(),
		InvalidStatus: invalidResp.StatusCode(),
	}

	// Check for IDOR indicators
	// 1. Both return 200 with data
	if validResp.StatusCode() == 200 && invalidResp.StatusCode() == 200 {
		// Check if response has data (not errors)
		if !containsGraphQLError(invalidResp.Body()) {
			result.IsVulnerable = true
			result.Evidence = "Both valid and invalid IDs return data without errors"
		}
	}

	return result, nil
}

// TestBatchIDOR tests for batch/aliasing IDOR attacks
// Processes IDs in batches of 50 to prevent memory issues
func (gt *GraphQLTester) TestBatchIDOR(queryName, idArgName string, ids []string) ([]string, error) {
	const maxBatchSize = 50

	var allVulnerable []string

	// Process in chunks
	for i := 0; i < len(ids); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(ids) {
			end = len(ids)
		}

		batch := ids[i:end]
		vulnerable, err := gt.testBatchChunk(queryName, idArgName, batch)
		if err != nil {
			continue
		}
		allVulnerable = append(allVulnerable, vulnerable...)
	}

	return allVulnerable, nil
}

// testBatchChunk tests a single batch of IDs
func (gt *GraphQLTester) testBatchChunk(queryName, idArgName string, ids []string) ([]string, error) {
	// Build batch query with aliases
	var queryParts []string
	for i, id := range ids {
		alias := fmt.Sprintf("q%d", i)
		queryParts = append(queryParts, fmt.Sprintf(`%s: %s(%s: "%s") { id }`, alias, queryName, idArgName, id))
	}

	batchQuery := GraphQLQuery{
		Query: fmt.Sprintf("query { %s }", strings.Join(queryParts, " ")),
	}

	resp, err := gt.executeQuery(batchQuery)
	if err != nil {
		return nil, err
	}

	// Parse response to find which IDs returned data
	var vulnerableIDs []string
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		for i, id := range ids {
			alias := fmt.Sprintf("q%d", i)
			if data[alias] != nil {
				vulnerableIDs = append(vulnerableIDs, id)
			}
		}
	}

	return vulnerableIDs, nil
}

// IDORResult represents GraphQL IDOR test result
type IDORResult struct {
	QueryName     string
	ValidStatus   int
	InvalidStatus int
	IsVulnerable  bool
	Evidence      string
}

func (gt *GraphQLTester) executeQuery(query GraphQLQuery) (*resty.Response, error) {
	return gt.client.Request().
		SetHeader("Content-Type", "application/json").
		SetBody(query).
		Post(gt.endpoint)
}

func isIDArgument(name string) bool {
	idPatterns := []string{"id", "userId", "user_id", "accountId", "resourceId", "objectId"}
	nameLower := strings.ToLower(name)
	for _, p := range idPatterns {
		if strings.Contains(nameLower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func containsGraphQLError(body []byte) bool {
	return strings.Contains(string(body), `"errors"`)
}

// ExtractQueriesFromSchema extracts potential IDOR-vulnerable queries
func (gt *GraphQLTester) ExtractQueriesFromSchema(schema string) []string {
	// Find queries with ID arguments
	re := regexp.MustCompile(`(\w+)\s*\(\s*(?:id|userId|user_id|.*Id)\s*:`)
	matches := re.FindAllStringSubmatch(schema, -1)

	var queries []string
	for _, m := range matches {
		if len(m) > 1 {
			queries = append(queries, m[1])
		}
	}
	return queries
}
