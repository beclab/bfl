package task

import (
	"sync"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"

	"github.com/pkg/errors"
)

var (
	once sync.Once

	LocalTaskQueue *TaskQueue
)

type LocalTaskInterface interface {
	Execute()
}

type TaskQueue struct {
	sync.Mutex
	l int

	s     []string // unique task name
	tasks []LocalTaskInterface
}

func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		Mutex: sync.Mutex{},
		l:     0,
		s:     make([]string, 0),
		tasks: make([]LocalTaskInterface, 0),
	}
}

func (q *TaskQueue) Len() int {
	q.Lock()
	defer q.Unlock()

	return q.l
}

func (q *TaskQueue) Push(name string, t LocalTaskInterface) error {
	q.Lock()
	defer q.Unlock()

	for i := 0; i < q.l; i++ {
		if q.s[i] == name {
			return errors.Errorf("task %v is already exists", name)
		}
	}

	q.s = append(q.s, name)
	q.tasks = append(q.tasks, t)
	q.l += 1
	return nil
}

func (q *TaskQueue) Pop() (string, LocalTaskInterface) {
	q.Lock()
	defer q.Unlock()

	if q.l == 0 {
		return "", nil
	}

	n, t := q.s[0], q.tasks[0]

	if q.l == 1 {
		q.s = make([]string, 0)
		q.tasks = make([]LocalTaskInterface, 0)
	} else {
		q.s = q.s[1:]
		q.tasks = q.tasks[1:]
	}
	q.l -= 1
	return n, t
}

func init() {
	once.Do(func() {
		LocalTaskQueue = NewTaskQueue()
	})
}

func Run() {
	for {
		name, t := LocalTaskQueue.Pop()

		if t == nil || name == "" {
			time.Sleep(1 * time.Second)
			continue
		}

		log.Infof("starting execute task %q ...", name)

		go func() {
			defer func() {
				if e := recover(); e != nil {
					log.Errorf("execute task %q: %v", name, e)
				}
			}()

			t.Execute()
		}()
	}
}
