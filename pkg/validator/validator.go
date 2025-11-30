package validator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

type Validator struct {
	validate *validator.Validate
}

func NewValidator() *Validator {
	return &Validator{
		validate: validator.New(),
	}
}

func (v *Validator) Validate(i interface{}) error {
	if err := v.validate.Struct(i); err != nil {
		var validationErrs validator.ValidationErrors
		if errors.As(err, &validationErrs) {
			return formatValidationErrors(validationErrs)
		}
		return err
	}
	return nil
}

func formatValidationErrors(errs validator.ValidationErrors) error {
	var messages []string
	for _, err := range errs {
		var message string
		field := strings.ToLower(err.Field())

		switch err.Tag() {
		case "required":
			message = fmt.Sprintf("%s is required", field)
		case "email":
			message = fmt.Sprintf("%s must be a valid email address", field)
		case "min":
			message = fmt.Sprintf("%s must be at least %s characters", field, err.Param())
		case "max":
			message = fmt.Sprintf("%s must be at most %s characters", field, err.Param())
		case "uuid":
			message = fmt.Sprintf("%s must be a valid UUID", field)
		case "gte":
			message = fmt.Sprintf("%s must be greater than or equal to %s", field, err.Param())
		case "lte":
			message = fmt.Sprintf("%s must be less than or equal to %s", field, err.Param())
		default:
			message = fmt.Sprintf("%s failed validation for %s", field, err.Tag())
		}
		messages = append(messages, message)
	}

	return errors.New(strings.Join(messages, "; "))
}
