package database

/*
import (
	"reflect"
	"routerDemo/models"
	"testing"
)

func Test_initializeNewClient(t *testing.T) {
	// Defining our test slice. Each unit test should have the following properties:
	tests := []struct {
		name    string       // The name of the test
		want    *TokenData   // What out instance we want our function to return.
		wantErr bool         // whether we want an error.
		user    *models.User // The input of the test
	}{
		// Here we're declaring each unit test input and output data as defined before
		{
			"success",
			&TokenData{UserId: "000000000000000000000001", GroupId: "000000000000000000000011", Role: "member", RootAdmin: false},
			false,
			&models.User{Id: "000000000000000000000001", GroupId: "000000000000000000000011", Role: "member", RootAdmin: false},
		},
		{"invalid user",
			&TokenData{},
			true,
			&models.User{Id: "000000000000000000000000", GroupId: "000000000000000000000012", Role: "member", RootAdmin: false},
		},
	}
	// Iterating over the previous test slice
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := InitUserToken(tt.user)
			// Checking the error
			if (err != nil) != tt.wantErr {
				t.Errorf("InitUserToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) { // Asserting whether we get the correct wanted value
				t.Errorf("InitUserToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
*/
