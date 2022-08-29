package main

import (
	"fmt"

	"github.com/go-playground/validator"
)

type Test struct {
	Email  string `validate:"required,email"`
	Server string `validate:"required,url"`
}

var validate *validator.Validate

func main() {
	validate = validator.New()

	valid := Test{
		Email:  "sam@test.org",
		Server: "https://www.test.org/",
	}
	invalid := Test{
		Email:  "adasdasd",
		Server: "asddasd",
	}

	err := validate.Struct(valid)
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Println("Valid!")
	}

	err = validate.Struct(invalid)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
}
