package cmd

import (
	"encoding/json"
	"os"
)

// Configuration is a struct designed to hold the applications variable configuration settings
type Configuration struct {
	MongoURI     string
	Database     string
	TokenSecret  string
	RootAdmin    string
	RootPassword string
	RootEmail    string
	RootGroup    string
	Registration string
}

// ConfigurationSettings is a function that reads a json configuration file and outputs a Configuration struct
func ConfigurationSettings() (*Configuration, error) {
	confFile := "confs.json"
	file, _ := os.Open(confFile)
	decoder := json.NewDecoder(file)
	configurationSettings := Configuration{}
	err := decoder.Decode(&configurationSettings)
	if err != nil {
		return &configurationSettings, err
	}
	return &configurationSettings, nil
}

// InitializeEnvironmentalVars initializes the environmental variables for the application
func (c *Configuration) InitializeEnvironmentalVars() {
	os.Setenv("MONGO_URI", c.MongoURI)
	os.Setenv("DATABASE", c.Database)
	os.Setenv("TOKEN_SECRET", c.TokenSecret)
	os.Setenv("ROOT_ADMIN", c.RootAdmin)
	os.Setenv("ROOT_PASSWORD", c.RootPassword)
	os.Setenv("ROOT_EMAIL", c.RootEmail)
	os.Setenv("ROOT_GROUP", c.RootGroup)
	os.Setenv("REGISTRATION", c.Registration)
}
