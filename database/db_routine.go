package database

import (
	"fmt"
	"sync"
)

type routineType int64

const (
	FindOne routineType = iota
	UpdateOne
	InsertOne
	DeleteOne
)

// dbRoutine struct to store executing thread ...
type dbRoutine[T dbModel] struct {
	out      T
	err      error
	oChannel chan T
	eChannel chan error
	handler  *DBHandler[T]
	rType    routineType
	filter   T
	data     T
}

// worker
func (p *dbRoutine[T]) worker(done chan T, doneErr chan error, wg *sync.WaitGroup) {
	defer wg.Done()
	var resp T
	var err error
	switch p.rType {
	case FindOne:
		fmt.Println("\n\nWE ARE HERE!")
		resp, err = p.handler.FindOne(p.filter)
		fmt.Println("\n\nWE ARE HERE OUTPUT! ", resp, err)
	case UpdateOne:
		resp, err = p.handler.UpdateOne(p.filter, p.data)
	case InsertOne:
		resp, err = p.handler.InsertOne(p.data)
	case DeleteOne:
		resp, err = p.handler.DeleteOne(p.filter)
	}
	fmt.Println("\nWE ARE HERE B!")
	doneErr <- err
	done <- resp
	//<-doneErr
	//<-done
	fmt.Println("\nWE ARE HERE C!")
	close(doneErr)
	close(done)
	fmt.Println("\nAT THE END OF THE WORKER")
}

// execute a DB Routine by inputting a RoutineType, filter, and data
func (p *dbRoutine[T]) execute(rt routineType, f T, d T, wg *sync.WaitGroup) {
	p.rType = rt
	p.filter = f
	p.data = d
	done := make(chan T)
	doneErr := make(chan error)
	//p.oChannel = make(chan T)
	//p.eChannel = make(chan error)
	go p.worker(done, doneErr, wg)
	fmt.Println("\nWE ARE HERE D!")
	select {
	case o := <-done:
		p.out = o
	case e := <-doneErr:
		p.err = e
	}
	//p.oChannel = done
	//p.eChannel = doneErr
	//p.out = <-done
	//p.err = <-doneErr
	fmt.Println("\nWE ARE HERE F!")
	//close(doneErr)
	//close(done)
}

// resolve an executing dbRoutine
func (p *dbRoutine[T]) resolve() {
	select {
	case o := <-p.oChannel:
		p.out = o
	case e := <-p.eChannel:
		p.err = e
	}
}
