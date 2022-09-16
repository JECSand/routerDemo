package main

func main() {
	var app App
	err := app.Initialize()
	if err != nil {
		panic(err)
	}
	app.Run()
}
