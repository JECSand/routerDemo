package database

import (
	"reflect"
	"routerDemo/models"
	"testing"
)

func Test_GroupCreate(t *testing.T) {
	// Defining our test slice. Each unit test should have the following properties:
	tests := []struct {
		name    string        // The name of the test
		want    *models.Group // What out instance we want our function to return.
		wantErr bool          // whether we want an error.
		group   *models.Group // The input of the test
	}{
		// Here we're declaring each unit test input and output data as defined before
		{
			"success",
			&models.Group{Id: "000000000000000000000001", Name: "test", RootAdmin: false},
			false,
			&models.Group{Id: "000000000000000000000001", Name: "test", RootAdmin: false},
		},
		{
			"missing name",
			&models.Group{Id: "000000000000000000000002", RootAdmin: false},
			true,
			&models.Group{Id: "000000000000000000000002", RootAdmin: false},
		},
	}
	// Iterating over the previous test slice
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testService := initTestGroupService()
			// fmt.Println("\n\nPRE CREATE: ", tt.group)
			got, err := testService.GroupCreate(tt.group)
			// fmt.Println("\nPOST CREATE: ", got)
			// Checking the error
			if (err != nil) != tt.wantErr {
				t.Errorf("GroupService.GroupCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !got.CreatedAt.IsZero() && !got.LastModified.IsZero() {
					tt.want.CreatedAt = got.CreatedAt
					tt.want.LastModified = got.LastModified
				}
			}
			if !reflect.DeepEqual(got, tt.want) { // Asserting whether we get the correct wanted value
				t.Errorf("GroupService.GroupCreate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GroupsFind(t *testing.T) {
	// Defining our test slice. Each unit test should have the following properties:
	tests := []struct {
		name    string // The name of the test
		want    int    // What out instance we want our function to return.
		wantErr bool   // whether we want an error.
	}{
		// Here we're declaring each unit test input and output data as defined before
		{
			"success",
			2,
			false,
		},
	}
	// Iterating over the previous test slice
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testService := setupTestFindGroups()
			got, err := testService.GroupsFind()
			// fmt.Println("\nPOST CREATE: ", got)
			// Checking the error
			if (err != nil) != tt.wantErr {
				t.Errorf("GroupService.GroupsFind() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.want { // Asserting whether we get the correct wanted value
				t.Errorf("GroupService.GroupsFind() = %v, want %v", len(got), tt.want)
			}
		})
	}
}
