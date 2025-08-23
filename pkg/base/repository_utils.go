package base

import (
	"reflect"
	"strings"

	"github.com/holycann/sso-kawasan-digital/pkg/errors"
	"github.com/holycann/sso-kawasan-digital/pkg/response"
	"github.com/holycann/sso-kawasan-digital/pkg/validator"
)

// ValidateModel performs comprehensive validation for a model
func ValidateModel[T any](model T) error {
	if err := validator.ValidateStruct(model); err != nil {
		return errors.Wrap(err,
			errors.ErrValidation,
			"Model validation failed",
			errors.WithContext("validation_errors", err.Error()),
		)
	}
	return nil
}

// BuildFilterFromStruct dynamically creates filter options from a struct
func BuildFilterFromStruct[T any](model T) []FilterOption {
	v := reflect.ValueOf(model)
	t := v.Type()
	var filters []FilterOption

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip zero/empty values
		if IsZero(field.Interface()) {
			continue
		}

		// Use field name as filter key
		filters = append(filters, FilterOption{
			Field:    strings.ToLower(fieldType.Name),
			Operator: OperatorEqual,
			Value:    field.Interface(),
		})
	}

	return filters
}

// PaginateResults applies pagination to a slice of results
func PaginateResults[T any](
	results []T,
	page, perPage int,
) ([]T, *response.Pagination) {
	total := len(results)

	// Calculate pagination
	start := (page - 1) * perPage
	end := start + perPage

	if start > total {
		return []T{}, &response.Pagination{
			Total:       total,
			Page:        page,
			PerPage:     perPage,
			TotalPages:  (total + perPage - 1) / perPage,
			HasNextPage: false,
		}
	}

	if end > total {
		end = total
	}

	paginatedResults := results[start:end]

	return paginatedResults, &response.Pagination{
		Total:       total,
		Page:        page,
		PerPage:     perPage,
		TotalPages:  (total + perPage - 1) / perPage,
		HasNextPage: end < total,
	}
}
